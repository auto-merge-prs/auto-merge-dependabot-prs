**THIS IS AN EXPERIMENTAL AND INTERNAL PREVIEW AND NOT INDENTED FOR GENERAL USE YET.**

This GitHub App enables auto-merge on PRs that dependabot opens so that they are merged automatically if CI passes.

## Installation

1. Click the *Configure* button to the right.
2. Select the repository for which you want to auto-merge dependabot PRs.
3. Click the *Install* button.
4. Done!

Now when dependabot[^1] opens a PR this app will automatically enable auto-merge for that PR.

## Security

Using this GitHub App is more secure than using a `pull_request_target`-triggered GitHub Actions workflow with a *Personal Access Token (PAT)* because:

* No `pull_request_target`-triggered workflow is needed so the risk of [pwn requests](https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/) is reduced.
* The credentials never enter any GitHub Actions workflow so the risk for credential leak is very low.
* Even if the credentials leak the permissions are minimal (`pull_request` and `content`[^2]).

## Terms of Service

THIS IS AN EXPERIMENTAL AND INTERNAL PREVIEW AND NOT INDENTED FOR GENERAL USE YET.

THIS APP MAY CEASE TO EXIST AT ANY POINT IN TIME.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

## Acknowledgements

The logo is [this](https://github.com/microsoft/fluentui-emoji/blob/main/assets/Rocket/3D/rocket_3d.png) image under [this](https://github.com/microsoft/fluentui-emoji/blob/main/LICENSE) license.

[^1]: `"user": { "login": "dependabot[bot]", "id": 49699333 }`
[^2]: The quite broad `contents` permission is unfortunately [needed](https://docs.github.com/en/rest/pulls/pulls?apiVersion=2022-11-28#merge-a-pull-request) to merge pull requests.
