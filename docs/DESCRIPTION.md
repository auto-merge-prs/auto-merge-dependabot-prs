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

### Auditing

As far as I know, if you monitor your repo for activity you will see all actions this app can take. So even if this app is malicious (or is taken over by a malicious party) it can't do anything sneaky.

Exception: If you publish binaries along with your GitHub Releases I think this app could silently replace those binaries with backdoored versions if it were malicious (but it isn't).

## Terms of Service

THIS IS AN EXPERIMENTAL AND INTERNAL PREVIEW AND NOT INDENTED FOR GENERAL USE YET.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

## Acknowledgements

The logo is [this](https://github.com/microsoft/fluentui-emoji/blob/main/assets/Rocket/3D/rocket_3d.png) image under [this](https://github.com/microsoft/fluentui-emoji/blob/main/LICENSE) license.

[^1]: `"user": { "login": "dependabot[bot]", "id": 49699333 }`
[^2]: `content` is unfortunately needed to be able to merge pull requests.
