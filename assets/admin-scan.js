(function () {
	document.querySelectorAll('.amsec-scan-form').forEach(function (form) {
		form.addEventListener('submit', function (event) {
			if (!window.fetch || !window.DOMParser) {
				return;
			}
			event.preventDefault();
			var button = form.querySelector('.amsec-scan-button');
			var progress = form.querySelector('.amsec-scan-progress');
			var fill = form.querySelector('.amsec-scan-fill');
			var stage = form.closest('.amsec-scan-first');
			// While a scan runs, only its progress shows. The new results appear when the page reloads with them.
			var screen = form.closest('.amsec-scan');
			var restore = function () {
				if (screen) {
					screen.classList.remove('is-scanning');
				}
			};
			if (screen) {
				screen.classList.add('is-scanning');
			}
			if (button) {
				button.hidden = true;
				button.disabled = true;
			}
			if (progress) {
				progress.hidden = false;
			}
			fetch(form.getAttribute('action'), {
				method: 'POST',
				body: new FormData(form),
				credentials: 'same-origin',
				redirect: 'follow'
			}).then(function (response) {
				return response.text().then(function (html) {
					return { response: response, html: html };
				});
			}).then(function (result) {
				if (fill) {
					fill.classList.add('is-done');
				}
				window.setTimeout(function () {
					var doc = new DOMParser().parseFromString(result.html, 'text/html');
					var failed = result.response.url.indexOf('amazing_security_error=1') !== -1 || doc.querySelector('[data-amsec-scan-error]');
					if (stage && failed) {
						restore();
						if (progress) {
							progress.hidden = true;
						}
						if (button) {
							button.hidden = false;
							button.disabled = false;
						}
						if (!stage.querySelector('[data-amsec-scan-error]')) {
							var notice = document.createElement('div');
							var copy = document.createElement('p');
							notice.className = 'notice notice-error';
							notice.setAttribute('data-amsec-scan-error', '');
							copy.textContent = (window.amsecScan && window.amsecScan.error) || 'Scan could not be saved.';
							notice.appendChild(copy);
							stage.insertBefore(notice, stage.firstChild);
						}
						return;
					}
					window.location.assign(result.response.url || window.location.href);
				}, 240);
			}).catch(function () {
				restore();
				if (progress) {
					progress.hidden = true;
				}
				if (button) {
					button.hidden = false;
					button.disabled = false;
				}
			});
		});
	});
}());
