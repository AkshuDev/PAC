const vscode = require("vscode");
const path = require("path");

const {
    LanguageClient,
    TransportKind
} = require("vscode-languageclient/node");

let client;

function activate(context) {
    const serverModule = context.asAbsolutePath(
        path.join("server.js")
    );

    client = new LanguageClient(
        "pac-lsp",
        "PAC LSP",
        {
            run: {
                module: serverModule,
                transport: TransportKind.ipc
            },
            debug: {
                module: serverModule,
                transport: TransportKind.ipc
            }
        },
        {
            documentSelector: [{ scheme: "file", language: "pasm" }]
        }
    );

    client.start();
}

function deactivate() {
    if (client) client.stop();
}

module.exports = { activate, deactivate };