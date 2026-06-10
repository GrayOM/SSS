# SSS Generalization Corpus

This corpus is engineering metadata, not a trained model and not a vendored copy of public projects.
External repositories are cloned under `.external_corpus/`, which is ignored by git.
Only derived pattern counts, representative fixture names, and support notes are stored here.

## Sources Inspected

### juice-shop

- Local path: `.external_corpus/juice-shop`
- License note: MIT license in repository metadata/source headers
- Source-like files inspected: 711
- Pattern counts:
  - `angular_httpclient`: 30
  - `dom_listener`: 2
  - `dom_sink`: 10
  - `dom_source`: 1
  - `fetch`: 17
  - `formdata`: 4
  - `html_form_action`: 2
  - `route_param`: 151
  - `storage`: 50
- Example files by pattern:
  - `angular_httpclient`: `frontend/src/app/Services/address.service.ts`, `frontend/src/app/Services/administration.service.ts`, `frontend/src/app/Services/basket.service.ts`, `frontend/src/app/Services/captcha.service.ts`, `frontend/src/app/Services/challenge.service.ts`
  - `dom_listener`: `frontend/src/hacking-instructor/index.ts`, `frontend/src/hacking-instructor/helpers/helpers.ts`
  - `dom_sink`: `frontend/src/app/data-export/data-export.component.ts`, `frontend/src/assets/private/dat.gui.min.js`, `frontend/src/assets/private/stats.min.js`, `frontend/src/hacking-instructor/index.ts`, `frontend/src/hacking-instructor/helpers/helpers.ts`
  - `dom_source`: `frontend/src/hacking-instructor/helpers/helpers.ts`
  - `fetch`: `frontend/src/hacking-instructor/helpers/helpers.ts`, `lib/webhook.ts`, `lib/startup/validatePreconditions.ts`, `routes/profileImageUrlUpload.ts`, `test/api/internet-resources.test.ts`
  - `formdata`: `server.ts`, `frontend/src/app/Services/photo-wall.service.ts`, `test/cypress/e2e/complain.spec.ts`, `test/cypress/e2e/profile.spec.ts`
  - `html_form_action`: `test/cypress/e2e/profile.spec.ts`, `views/dataErasureForm.hbs`
  - `route_param`: `Gruntfile.js`, `server.ts`, `data/datacreator.ts`, `data/static/codefixes/accessLogDisclosureChallenge_1_correct.ts`, `data/static/codefixes/accessLogDisclosureChallenge_2.ts`
  - `storage`: `frontend/src/app/app.guard.spec.ts`, `frontend/src/app/app.guard.ts`, `frontend/src/app/address/address.component.ts`, `frontend/src/app/basket/basket.component.ts`, `frontend/src/app/change-password/change-password.component.ts`

### nodegoat

- Local path: `.external_corpus/nodegoat`
- License note: OWASP intentionally vulnerable training application; inspect repository license before redistributing source
- Source-like files inspected: 74
- Pattern counts:
  - `dom_sink`: 6
  - `dom_source`: 2
  - `html_form_action`: 6
  - `jquery_event`: 3
  - `route_param`: 10
- Example files by pattern:
  - `dom_sink`: `app/assets/vendor/html5shiv.js`, `app/assets/vendor/jquery.min.js`, `app/assets/vendor/chart/raphael-min.js`, `app/routes/contributions.js`, `app/views/tutorial/a1.html`
  - `dom_source`: `app/assets/vendor/jquery.min.js`, `app/assets/vendor/bootstrap/bootstrap-tour.js`
  - `html_form_action`: `app/views/allocations.html`, `app/views/benefits.html`, `app/views/contributions.html`, `app/views/memos.html`, `app/views/profile.html`
  - `jquery_event`: `app/assets/js/tour/redirects-steps.js`, `app/assets/vendor/bootstrap/bootstrap.js`, `app/assets/vendor/chart/morris-0.4.3.min.js`
  - `route_param`: `server.js`, `app/assets/vendor/jquery.min.js`, `app/data/allocations-dao.js`, `app/data/user-dao.js`, `app/routes/index.js`

## Pattern Taxonomy

- API calls: fetch, axios, Angular HttpClient, jQuery ajax, object-style wrappers, named api/client wrappers.
- Endpoint construction: literals, base URL aliases, template route params, concatenated aliases, HTML form actions.
- UI mapping: React handlers, Vue handlers, jQuery `.on`, DOM `addEventListener`, form submit buttons.
- Payloads: inline objects, payload variables, FormData append, URLSearchParams append, form input names.
- Browser proof targets: payment/order mutations, wallet/value mutations, ID route params, account recovery, DOM XSS, storage/auth branches.
- Noise: session/init/search/recommendation, analytics/static assets, vendor/minified/runtime code.

## Derived Fixtures

- `scripts/verify_generalization.py` contains minimal derived snippets for Angular HttpClient, HTML form actions, API wrappers, FormData, URLSearchParams, DOM XSS, storage auth, and noise/destructive cases.
- `scripts/verify_realistic_output.py` contains product-direction fixtures for payment, auction, wallet, Iamport, Stripe, recovery, login, route params, and destructive endpoints.

## Supported Patterns

- Direct helper-free promoted API PoCs for concrete fetch/axios/jQuery/wrapper/Angular HttpClient calls.
- Editable route constants for stable route params.
- Base URL normalization for common and alias-derived paths.
- Manual demotion for uncertain wrappers, destructive endpoints, build artifacts, and generic/noisy GETs.
- DOM source/sink and storage/auth branch extraction with browser-console-oriented proof output.

## Unsupported Or Future Work

- Full inter-file call graph from component method to injected service method is still heuristic.
- Complex Angular observable pipelines and generated OpenAPI clients need richer parsing.
- Server-rendered forms can be extracted, but browser-verifiable promotion remains conservative when no handler context exists.
- Dynamic endpoint builders with non-literal route fragments still require manual Network-tab validation.
