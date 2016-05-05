var http = require('http');
var https = require('https');
var url = require('url');
var extend = require('util')._extend;

var results = {
    all: 0,
    accAll: 0,
    csp: 0,
    accCsp: 0
};
var defaultOptions = {
    method: 'HEAD',
    path: '/',
    headers: {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.94 Safari/537.36"
    }
};

// load list of URLs
var inputDataPath = process.argv[2] || '';
if (!inputDataPath) {
    console.log("Usage:\nnode csp-analyser.js <relative_path_to_input_data_json_file>");
    process.exit(1);
}
var urlList = require('./' + inputDataPath);

var countFinished = 0;
var BATCH_SIZE = 10;        // max no. of concurrent requests
var REDIRECTS_LIMIT = 10;
var currentBatch = 0;

// make requests
prepareNextBulk();

//
function prepareNextBulk() {
    var bulk = urlList.slice(currentBatch * BATCH_SIZE, currentBatch * BATCH_SIZE + BATCH_SIZE);
    currentBatch++;
    
    if (bulk.length) {
        console.log("-- Processing batch #" + currentBatch + " ...");
        processBulkOfRequests(bulk);    
    } else {
        console.log("-- Finished");
        processResult();
        process.exit();
    }
}

function processBulkOfRequests(bulk) {
    countUrls = bulk.length;
    countFinished = 0;

    bulk.forEach(function(website) {
        var options = getRequestOptions(website.url);
        var request = makeRequest(options, findCSP, website);
    });
}

function makeRequest(options, cb, website) {
    var engine = (website.ssl) ? https : http;
    var request = engine.request(options, function(response) {
        if ("location" in response.headers) {
            fillOptionsBasedOnLocationUri(response.headers.location, options);
            website.ssl = checkForHTTPS(response.headers.location);
            website.countRedirects = website.countRedirects || 0;
            if (website.countRedirects >= REDIRECTS_LIMIT) {
                console.log("[" + response.headers["host"] + "] redirects limit has been exceeded");
                evalStopCondition();
                return;
            }
            website.countRedirects++;
            makeRequest(options, cb, website);
            return;
        }

        results.all++;
        results.accAll += website.traffic;
        
        cb(response.headers, website);
        
        evalStopCondition();
    }).on('error', function(e) {
        console.log("[" + this.getHeader("Host") + "] Error: " + e.message);
        evalStopCondition();
    });
    request.end();
    return request;
}

function getRequestOptions(host) {
    var options = extend({host: host}, defaultOptions);
    return options;
}

function findCSP(headers, website) {
    if ( !("content-security-policy" in headers) ) {
        return;
    }
    results.csp++;
    results.accCsp += website.traffic;
    console.log("CSP has been found on: " + website.url + " [" + headers["content-security-policy"] + "]");
}

function evalStopCondition() {
    countFinished++;
    if (countFinished === countUrls) {
        prepareNextBulk();
    }
}

function fillOptionsBasedOnLocationUri(locationUri, options) {
    var urlParts = url.parse(locationUri);
    options.host = urlParts.hostname;
    options.port = urlParts.port;
    options.path = urlParts.path;
}

function checkForHTTPS(locationUri) {
    var urlParts = url.parse(locationUri);
    return ("https:" === urlParts.protocol);
}

function processResult() {
    console.log(JSON.stringify(results));
}
