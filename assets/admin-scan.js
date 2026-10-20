(function () {
	var settings = window.amsecScan || {};

	// One row per real check, in scan order. The homepage-headers row only appears when that setting is on.
	var buildList = function (form, list) {
		var items = (settings.checks || []).slice();
		if (form.getAttribute('data-amsec-headers') === '1' && settings.headers) {
			items.push(settings.headers);
		}
		items.push(settings.saving || 'Saving the results');
		list.textContent = '';
		return items.map(function (label, index) {
			var row = document.createElement('li');
			var dot = document.createElement('span');
			var number = document.createElement('span');
			var name = document.createElement('span');
			dot.className = 'amsec-scan-dot';
			dot.setAttribute('aria-hidden', 'true');
			number.className = 'amsec-scan-num';
			number.textContent = String(index + 1);
			name.className = 'amsec-scan-name';
			name.textContent = label;
			row.setAttribute('data-state', 'pending');
			row.appendChild(dot);
			row.appendChild(number);
			row.appendChild(name);
			list.appendChild(row);
			return row;
		});
	};

	document.querySelectorAll('.amsec-scan-form').forEach(function (form) {
		form.addEventListener('submit', function (event) {
			if (!window.fetch || !window.DOMParser) {
				return;
			}
			event.preventDefault();
			var button = form.querySelector('.amsec-scan-button');
			var progress = form.querySelector('.amsec-scan-progress');
			var fill = form.querySelector('.amsec-scan-fill');
			var percent = form.querySelector('.amsec-scan-percent');
			var track = form.querySelector('.amsec-scan-track');
			var list = form.querySelector('.amsec-scan-list');
			var step = form.querySelector('.amsec-scan-step');
			var stop = form.querySelector('.amsec-scan-stop');
			var stage = form.closest('.amsec-scan-first');
			// While a scan runs, only its progress shows. The new results appear when the page reloads with them.
			var screen = form.closest('.amsec-scan');
			var rows = list ? buildList(form, list) : [];
			var controller = window.AbortController ? new AbortController() : null;
			var body = new FormData(form);
			var started = Date.now();
			var minMs = settings.minMs || 36000;
			var finished = null;
			var timer = null;
			var restore = function () {
				window.clearInterval(timer);
				form.classList.remove('is-scanning');
				if (screen) {
					screen.classList.remove('is-scanning');
				}
				if (progress) {
					progress.hidden = true;
				}
				if (button) {
					button.hidden = false;
					button.disabled = false;
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
				// Row i is active while the bar is inside its share of 100%, done once the bar passes it.
				var active = value >= 100 ? rows.length : Math.min(rows.length - 1, Math.floor(value / 100 * rows.length));
				rows.forEach(function (row, index) {
					var state = index < active ? 'done' : (index === active ? 'active' : 'pending');
					if ('active' === state && step) {
						step.textContent = (settings.step || 'Step %1$s of %2$s').replace('%1$s', String(index + 1)).replace('%2$s', String(rows.length)) + ': ' + row.lastChild.textContent;
					}
					if (row.getAttribute('data-state') !== state) {
						row.setAttribute('data-state', state);
						if ('active' === state && list) {
							// Keep the active row in view inside the list without moving the page.
							list.scrollTop = Math.max(0, row.offsetTop - list.offsetTop - list.clientHeight / 2);
						}
					}
				});
			};
			draw(0);
			timer = window.setInterval(function () {
				var elapsed = Date.now() - started;
				// Hold at 99% until the server has answered; never claim 100% before the results are saved.
				if (finished && elapsed >= minMs) {
					window.clearInterval(timer);
					draw(100);
					if (step) {
						step.textContent = (settings.step || 'Step %1$s of %2$s').replace('%1$s', String(rows.length)).replace('%2$s', String(rows.length));
					}
					finished();
					return;
				}
				draw(Math.min(99, Math.floor(elapsed / minMs * 100)));
			}, 120);
			if (stop) {
				stop.onclick = function () {
					if (controller) {
						controller.abort();
					}
					window.clearInterval(timer);
					// The request may already have saved results; reloading shows whatever is stored now.
					window.location.assign(window.location.href.split('#')[0]);
				};
			}
			fetch(form.getAttribute('action'), {
				method: 'POST',
				body: body,
				credentials: 'same-origin',
				redirect: 'follow',
				signal: controller ? controller.signal : undefined
			}).then(function (response) {
				return response.text().then(function (html) {
					return { response: response, html: html };
				});
			}).then(function (result) {
				var doc = new DOMParser().parseFromString(result.html, 'text/html');
				var failed = result.response.url.indexOf('amazing_security_error=1') !== -1 || doc.querySelector('[data-amsec-scan-error]');
				if (stage && failed) {
					// A failed save shows its error right away instead of finishing the walk-through.
					restore();
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
				finished = function () {
					window.setTimeout(function () {
						window.location.assign(result.response.url || window.location.href);
					}, 600);
				};
			}).catch(function (error) {
				if (!error || 'AbortError' !== error.name) {
					restore();
				}
			});
		});
	});
}());
