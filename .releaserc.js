const path = require("path");
const fs = require("fs");

const tplFile = path.resolve(__dirname, ".github/release-notes.hbs");

module.exports = {
  branches: ["main"],
  plugins: [
    [
      "semantic-release-gitmoji",
      {
        releaseRules: {
          patch: {
            include: [
              ":bento:",
              ":arrow_up:",
              ":lock:",
              ":bug:",
              ":ambulance:",
            ],
          },
        },
        releaseNotes: {
          template: fs.readFileSync(tplFile, "utf-8"),
        },
      },
    ],
    "@semantic-release/github",
    "@semantic-release/npm",
    [
      "@semantic-release/git",
      {
        message: [
          ":bookmark: v${nextRelease.version} [skip ci]",
          "",
          "https://github.com/djcrabhat/nist-password-checker/releases/tag/${nextRelease.gitTag}",
        ].join("\n"),
      },
    ],
    [
      "@semantic-release/exec",
      {
        publishCmd:
          'echo "${nextRelease.notes}" > /tmp/release-notes.md' +
          "\n" +
          "goreleaser release --release-notes /tmp/release-notes.md --clean",
      },
    ],
  ],
};
