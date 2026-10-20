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
				form.classList.remove('is-scanning');
				if (screen) {
					screen.classList.remove('is-scanning');
				}
			};
			form.classList.add('is-scanning');
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
			// The scan itself finishes in a second or two. The bar walks through the real check areas
			// at a readable pace so people can see what is being looked at.
			var settings = window.amsecScan || {};
			var stages = settings.stages || [];
			var minMs = settings.minMs || 20000;
			var percent = form.querySelector('.amsec-scan-percent');
			var stageLine = form.querySelector('.amsec-scan-stage');
			var track = form.querySelector('.amsec-scan-track');
			var started = Date.now();
			var shownStage = -1;
			var finished = null;
			if (fill) {
				fill.classList.add('is-determinate');
			}
			var draw = function (value) {
				if (fill) {
					fill.style.width = value + '%';
				}
				if (percent) {
					percent.textContent = value + '%';
				}
				if (track) {
					track.setAttribute('aria-valuenow', String(value));
				}
				var index = Math.min(stages.length - 1, Math.floor(value / 100 * stages.length));
				if (stageLine && index >= 0 && index !== shownStage) {
					shownStage = index;
					stageLine.textContent = stages[index];
				}
			};
			draw(0);
			var timer = window.setInterval(function () {
				var elapsed = Date.now() - started;
				// Hold at 99% until the server has answered; never claim 100% before the results are saved.
				var value = Math.min(99, Math.floor(elapsed / minMs * 100));
				if (finished && elapsed >= minMs) {
					window.clearInterval(timer);
					draw(100);
					finished();
					return;
				}
				draw(value);
			}, 120);
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
				var doc = new DOMParser().parseFromString(result.html, 'text/html');
				var failed = result.response.url.indexOf('amazing_security_error=1') !== -1 || doc.querySelector('[data-amsec-scan-error]');
				// A failed save shows its error right away instead of finishing the walk-through.
				if (stage && failed) {
					window.clearInterval(timer);
				}
				finished = function () {
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
							copy.textContent = settings.error || 'Scan could not be saved.';
							notice.appendChild(copy);
							stage.insertBefore(notice, stage.firstChild);
						}
						return;
					}
					window.setTimeout(function () {
						window.location.assign(result.response.url || window.location.href);
					}, 400);
				};
				if (stage && failed) {
					finished();
				}
			}).catch(function () {
				window.clearInterval(timer);
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
