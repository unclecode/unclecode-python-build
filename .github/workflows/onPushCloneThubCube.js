// actions on push on chub
const fs = require('fs');
const Octokit = require("@octokit/rest");
const axios = require("axios");
const shell = require("shelljs");
const crypto = require('crypto');

async function encryptAndPutAuthFile(username, repo, algorithm, gitToken, authPhrase, _silent) {
    try {
        var cipher = crypto.createCipher(algorithm, gitToken);
        var encryptedPhrase = cipher.update(authPhrase, 'utf8', 'hex');
        encryptedPhrase += cipher.final('hex');
        shell.exec(`git checkout master`, {silent: _silent});
        shell.exec(`echo ${encryptedPhrase} > auth`, {silent: _silent});
        shell.exec(`git add auth`, {silent: _silent});
        shell.exec(`git commit -m 'add auth file'`, {silent: _silent});
        shell.exec(`git push https://${username}:${gitToken}@github.com/${repo} master`, {silent: _silent});
        return true
    } catch (err) {
        throw err
    }
}

async function getUserTokenAndDecrypt(repo, algorithm, pwd) {
    try {
        let resp = await axios.get(`https://api.github.com/repos/${repo}/contents/auth`);
        if(!resp.data.content)
            throw new Error("No auth file found");
        let content = Buffer.from(resp.data.content, 'base64').toString('ascii').replace(/\n/g, "");
        var decipher = crypto.createDecipher(algorithm, pwd);
        var token = decipher.update(content, 'hex', 'utf8');
        token += decipher.final('utf8');
        return token;
    } catch (err) {
        throw err
    }
}


async function cloneTrainerBuiltCube(bHub, repo_name) {
    console.log(`Cloning from BHub...`);
    try {
        const cloneUrl = `https://github.com/${bHub}/${repo_name}`;
        const _silent = false;
        shell.exec(`git clone ${cloneUrl}`, { silent: _silent });
        return {
            result: true
        }
    } catch (err) {
        return {
            result: false,
            error: err.message
        }
    }
}

async function createLessons(cube, lessons, repo_name, token, bHub) {
    console.log(`Creating '${repo_name}' lessons...`);
    const _silent = false;

    try {
        process.chdir(process.cwd() +  `/${repo_name}`);

        for (let ix = 0; ix < lessons.length; ix++) {
            const lesson = lessons[ix];
            shell.exec(`git checkout --orphan ${lesson}`, { silent: _silent });
            shell.exec(`git rm -rf .`, { silent: _silent });
            shell.exec(`echo "${lesson}" > README.md`, { silent: _silent });
            shell.exec(`git add --all`, { silent: _silent });
            shell.exec(`git commit -m 'Initial ${lesson}'`, { silent: _silent });
        }

        shell.exec(`git checkout master`, { silent: _silent });

        cubeInfo = {};
        cubeInfo.index = lessons;
        fs.writeFileSync(`${cube}.cube.json`, JSON.stringify(cubeInfo, null, 4));
        
        shell.exec(`git add --all`, { silent: _silent });
        shell.exec(`git commit -m 'Add lessons'`, { silent: _silent });
        shell.exec(`git push https://${bHub}:${token}@github.com/${bHub}/${repo_name}.git --all`, { silent: _silent });
        
        console.log(`Done.`);

        return {
            result: true
        }

    } catch (err) {
        return {
            result: false,
            error: err.message
        }
    }
}

async function forkBhubCube(username, repo_name, bHub) {
    console.log("Forking to teacher repo...");
    try {
        // get teacher token
        const url = 'https://webhooks.mongodb-stitch.com/api/client/v2.0/app/kportal-grmuv/service/kportalWeb/incoming_webhook/getUserToken?secret=5eaae879cf';
        let response = await axios.post(url, {
            "username": username
        });
        let token = response.data['token'];
        let octokit = new Octokit({
            auth: "token " + token
        });
        await octokit.repos.createFork({
            owner: bHub,
            repo: repo_name
        });

        return {
            result: true,
            repoLink: `https://github.com/${username}/${repo_name}`
        }
    } catch (err) {
        return {
            result: false,
            error: err.message
        }
    }
}

async function enablePage(username, repo_name) {
    console.log("Enable git page...");
    try {
        // get teacher token
        const url = 'https://webhooks.mongodb-stitch.com/api/client/v2.0/app/kportal-grmuv/service/kportalWeb/incoming_webhook/getUserToken?secret=5eaae879cf';
        let response = await axios.post(url, {
            "username": username
        });
        let token = response.data['token'];
        let octokit = new Octokit({
            auth: "token " + token
        });
        
        // enable page
        await octokit.repos.enablePagesSite({
            owner: username,
            repo: repo_name,
            source: {
                "branch": "master",
                "path": "/docs"
            },
            headers: {
                accept: "application/vnd.github.switcheroo-preview+json"
            }
        })

        console.log("Done.");
        return {
            result: true,
            repoLink: `https://github.com/${username}/${repo_name}`
        }
    } catch (err) {
        return {
            result: false,
            error: "Couldn't enable page: " + err.message
        }
    }
}

async function deleteFile(owner, repo, path, message, branch, token) {
    try {
        let octokit = new Octokit({
            auth: "token " + token
        });
        let sha = (await octokit.repos.getContents({
            owner,
            repo,
            path,
            ref: branch
        })).data.sha;
        if (sha) {
            await octokit.repos.deleteFile({
                owner,
                repo,
                path,
                message,
                sha,
                branch
            });
            return true;
        } else {
            throw new Error(" no sha found to remove auth file in master branch in " + repo + "repo!");
        }
    } catch (err) {
        throw err
    }
}

let initCube = async (username, cube, lessons, repo, gitToken) => {
    const algorithm = 'aes256';
    const authPhrase = 'unclecode';
    const server = "https://cubie.now.sh";
    const bHub = 'kportal-hub';
    const _silent = false;

    // const KIDOCODE = "KidoCode";
    // const default_thub = 'default-thub';

    try {
        const repo_name = `${username}-${cube}-build`;

        // create encrypted auth file and send it to server to get tokens
        await encryptAndPutAuthFile(bHub, repo, algorithm, gitToken, authPhrase, _silent);

        // get token from server
        let authRes = (await axios.post(server + "/api/check-auth", {
            username,
            gitToken,
            repo: repo_name,
            path: `auth`,
            type: "c"
        })).data

        if (!authRes.result) {
            throw new Error("Unauthorized Access")
            // return false;
        } else {

            let r = await getUserTokenAndDecrypt(repo, algorithm, gitToken);
            const masterToken = r.split('\n')[1].split('=')[1]

            // ============================================== func 1 - clone cube from thub 
            let res = await cloneTrainerBuiltCube(bHub, repo_name);
            if (res.result) {
                // ========================================== func 2 - create a branch for each lesson
                await createLessons(cube, lessons, repo_name, masterToken, bHub);
                
                // ========================================== func 3 - delete auth file
                await deleteFile(
                    bHub, // owner
                    repo_name, // repo
                    "auth", // path
                    "delete auth file",
                    "master", // branch
                    masterToken
                );

                // ========================================== func 4 - fork cube repo for teacher
                await forkBhubCube(username, repo_name, bHub);

                // ========================================== func 5- enable page
                let resp = await enablePage(username, repo_name);

                return resp;
            }
            return res;
        }

    } catch (err) {
        console.log(`Couldn't create and fetch cube for ${cube}`, err)
        return false;
    }
}

const cubeOnPush = async (repo, gitToken) => {
    const cube = JSON.parse(fs.readFileSync(process.env.NODE_CUBE, 'utf8')).commits[0].message.split(".")[0];
    const username = JSON.parse(fs.readFileSync(`${cube}.user.json`, 'utf8')).username
    const lessons = JSON.parse(fs.readFileSync(`${cube}.user.json`, 'utf8')).lessons;
    
    return await initCube(username, cube, lessons, repo, gitToken)
}

cubeOnPush(process.argv[2], process.argv[3]).then((res) => {
    console.log(res)
})
