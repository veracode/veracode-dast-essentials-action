const axios = require('axios')
const core = require('@actions/core');
const fs = require('fs');
crypto = require("crypto");
const util = require('util')

// Load Configuration
const veracodeWebhook = core.getInput('VERACODE_WEBHOOK');
const id = core.getInput('VERACODE_SECRET_ID');
const key = core.getInput('VERACODE_SECRET_ID_KEY');
const region = core.getInput('REGION');
const pullReport = core.getInput('pull-report');

const preFix = "VERACODE-HMAC-SHA-256";
const verStr = "vcode_request_version_1";

let host = "api.veracode.com";
let urlPrefix = "/dae/api/core-api/webhook";

if(region === "eu") {
    host = "api.veracode.eu";
}

let hmac256 = async (data, key) => {
    let hash = crypto.createHmac('sha256', key).update(data);
    // no format = Buffer / byte array
    return hash.digest();
}

let getByteArray = (hex) => {
    let bytes = [];

    for(let i = 0; i < hex.length-1; i+=2){
        bytes.push(parseInt(hex.substr(i, 2), 16));
    }

    // signed 8-bit integer array (byte array)
    return Int8Array.from(bytes);
}

let generateHeader = async (url, method) => {

    let data = `id=${id}&host=${host}&url=${url}&method=${method}`;
    let timestamp = (new Date().getTime()).toString();
    let nonce = crypto.randomBytes(16).toString('hex');

    // calculate signature
    let hashedNonce = await hmac256(getByteArray(nonce), getByteArray(key));
    let hashedTimestamp = await hmac256(buffer(timestamp), getByteArray(hex(hashedNonce)));
    let hashedVerStr = await hmac256(buffer(verStr), getByteArray(hex(hashedTimestamp)));
    let signature = hex(await hmac256(buffer(data), getByteArray(hex(hashedVerStr))));

    return `${preFix} id=${id},ts=${timestamp},nonce=${nonce},sig=${signature}`;
}

const wait = function (milliseconds) {
    return new Promise((resolve) => {
        if (typeof milliseconds !== 'number') {
            throw new Error('milliseconds not a number');
        }
        setTimeout(() => resolve("done!"), milliseconds)
    });
};

// https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/digest#Converting_a_digest_to_a_hex_string
let hex = (buffer) => Array.from(new Uint8Array(buffer)).map(n => n.toString(16).padStart(2, "0")).join("");

let buffer = (string) => new TextEncoder("utf-8").encode(string);

async function run() {
    try {

        // Setup general variables
        const pollTimeout = 60000; // Polling the scan status every 60 seconds
        let status = 100; // 100 = Queued
        let scanId = undefined;
        let url = urlPrefix + "/" + veracodeWebhook;

        console.log(`Sending Webhook to URL ${host}${url} for ${veracodeWebhook}`);

        // Start the Security Scan
        try {
            let method = "POST";
            let VERACODE_AUTH_HEADER = await generateHeader(url, method);
            const callUrl = "https://" + `${host}${url}`
            console.log(`Calling following url: ${callUrl} to start a scan with auth header - ${VERACODE_AUTH_HEADER}`);
            const response = await axios.post(callUrl, "", {
                headers: {'Authorization': VERACODE_AUTH_HEADER},
            });
            console.log(`Start scan response: ${util.inspect(response, {depth: null})}`);
            scanId = response.data.data.scanId;
        } catch (error) {
            let errorMsg = error.toString()
            core.setFailed(`Could not start Scan for Webhook ${veracodeWebhook}. Reason: ${errorMsg}.`);
            return
        }

        // Check if the scan was correctly started
        if (!scanId) {
            core.setFailed(`Could not start Scan for Webhook ${veracodeWebhook}.`);
            return
        }

        console.log(`Started Scan for Webhook ${veracodeWebhook}. Scan ID is ${scanId}.`)

        // Check if the action should wait for the report and download it
        if (pullReport === 'false') {
            console.log(`Skipping the download of the scan report as pull-report='${pullReport}'.`);
            return
        }

        // Wait until the scan has finished
        while (status <= 101) {
            console.log(`Scan Status currently is ${status} (101 = Running)`);

            // Only poll every minute
            await wait(pollTimeout);

            // Refresh status
            try {
                const method = "GET";
                const url = urlPrefix + "/" + `${veracodeWebhook}/scans/${scanId}/status`;
                const callUrl = "https://" + `${host}${url}`
                const VERACODE_AUTH_HEADER = await generateHeader(url, method);

                console.log(`Calling following url to get scan status: ${callUrl} with auth header - ${VERACODE_AUTH_HEADER}`);
                const response = await axios.get(callUrl, {
                    headers: {'Authorization': VERACODE_AUTH_HEADER}, family: 4
                });
                console.log(`Response Data: ${util.inspect(response, {depth: null})}`);
                console.log(`Scan Status currently is ${response.data.data.status} (101 = Running)`);
                status = response.data.data.status.status_code;
                console.log(`Scan Status updated to: ${status}`);
            } catch (error) {
                console.log(`Response Data: ${util.inspect(response, {depth: null})}`);
                console.log(`Scan Status currently is ${response.data.data.status} (101 = Running)`);
                status = response.data.data.status.status_code;
                console.log(`Scan Status updated to: ${status}`);
                console.log(`HTTTP STATUS = ${error.response.status}`);
                core.setFailed(`Retreiving Scan Status failed for Webhook ${veracodeWebhook}. Reason: ${JSON.stringify(error)}.`);
                return
            }

        }

        console.log(`Scan finished with status ${status}.`)

        // Download the JUnit Report
        let junitReport = undefined;
        try {
            let method = "GET";
            let url = urlPrefix + "/" + `${veracodeWebhook}/scans/${scanId}/report/junit`;
            let VERACODE_AUTH_HEADER = await generateHeader(url, method);
            console.log(`Calling following url to get scan results: https:// + ${host}${url} with auth header - ${VERACODE_AUTH_HEADER}`);
            const response = await axios.get("https://" + `${host}${url}`, {
                headers: {'Authorization': VERACODE_AUTH_HEADER},
                family: 4
            });
            console.log(`Scan results: ${JSON.stringify(response)}`);
            junitReport = response.data;
        } catch (error) {
            console.log(`HTTTP STATUS = ${error.response.status}`);
            core.setFailed(`Downloading Report failed for Webhook ${veracodeWebhook}. Reason: ${error.toString()}.`);
            return
        }

        fs.writeFile('report.xml', junitReport, function (error) {
            if (error) {
                core.setFailed(`Writing the Report failed for Webhook ${veracodeWebhook}. Reason: ${error}`);
            }
        });

        console.log('Downloaded Report to report.xml');

    } catch (error) {
        core.setFailed(error.message);
        return
    }
}

run();
