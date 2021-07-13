const { readFileSync } = require("fs");

let karmaTypescriptConfig = {
    ...JSON.parse(readFileSync("./tsconfig.json", "utf8")),
    bundlerOptions: {
        transforms: [
            require("karma-typescript-es6-transform")({
                plugins: [
                    '@babel/plugin-transform-spread',
                    '@babel/plugin-transform-classes'],
                presets: [
                    ["env", {
                        targets: {
                            browsers: ["last 2 Chrome versions"]
                        }
                    }]
                ]
            })
        ]
    }
};

module.exports = function (config) {
    config.set({
        karmaTypescriptConfig,
        frameworks: ["mocha", "karma-typescript"],
        files: [
            { pattern: "node_modules/expect.js/index.js" },
            { pattern: "src/**/*.ts" },
            { pattern: "test/**/*.spec.ts" },
        ],
        preprocessors: {
            "**/*.ts": ["karma-typescript"]
        },
        reporters: ["dots", "karma-typescript"],
        browsers: ["ChromeHeadless"],
        singleRun: true
    });
};
