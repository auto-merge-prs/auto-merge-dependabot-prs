This GitHub App enables auto-merge on PRs that dependabot opens so that they are merged automatically if CI passes.

## Installation

1. Click the **Configure** button to the right.
2. Select the repository for which you want to auto-merge dependabot PRs.
3. Click the **Install** button.
4. Done!

Now when dependabot[^1] opens a PR this GitHub App will automatically enable auto-merge for that PR.

## Security

Using this GitHub App is more secure than using a `pull_request_target`-triggered GitHub Actions workflow with a *Personal Access Token (PAT)* because:

* No `pull_request_target`-triggered workflow is needed so the risk of [pwn requests](https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/) is reduced.
* The credentials never enter any GitHub Actions workflow so the risk for credential leak is very low.
* Even if the credentials leak the permissions are minimal (["Contents"](https://docs.github.com/en/rest/authentication/permissions-required-for-github-apps?apiVersion=2022-11-28#repository-permissions-for-contents) to auto-merge PRs and ["Pull requests"](https://docs.github.com/en/rest/authentication/permissions-required-for-github-apps?apiVersion=2022-11-28#repository-permissions-for-pull-requests) to comment on auto-merged PRs).

## Terms of Service

Consider [sponsoring](https://github.com/sponsors/Enselic) to cover operational costs.

I reserve the right to cease operations at any point in time. But if I do, you can deploy the app yourself since this bot is [open source](https://github.com/auto-merge-prs/auto-merge-dependabot-prs).

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

## Acknowledgements

The logo is [this](https://github.com/microsoft/fluentui-emoji/blob/main/assets/Rocket/3D/rocket_3d.png) image under [this](https://github.com/microsoft/fluentui-emoji/blob/main/LICENSE) license.

[^1]: `"user": { "login": "dependabot[bot]", "id": 49699333 }`
