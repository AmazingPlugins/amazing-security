(function () {
	var settings = window.amsecScan || {};

	// One row per step the server reported, in the order it runs them.
	var buildList = function (list, labels) {
		list.textContent = '';
		return labels.map(function (label, index) {
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

	var post = function (form, fields, signal) {
		var body = new FormData();
		body.append('action', 'amsec_scan_step');
		body.append('_ajax_nonce', form.querySelector('input[name="_wpnonce"]').value);
		Object.keys(fields).forEach(function (key) {
			body.append(key, fields[key]);
		});
		return fetch(settings.ajax, { method: 'POST', body: body, credentials: 'same-origin', signal: signal }).then(function (response) {
			return response.json().then(function (json) {
				if (!response.ok || !json || !json.success) {
					throw new Error('step');
				}
				return json.data;
			});
		});
	};

	document.querySelectorAll('.amsec-scan-form').forEach(function (form) {
		form.addEventListener('submit', function (event) {
			if (!window.fetch || !window.FormData || !settings.ajax || form.getAttribute('data-amsec-fallback')) {
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
			// While a scan runs, only its progress shows. The new results appear when the page reloads with them.
			var screen = form.closest('.amsec-scan');
			var controller = window.AbortController ? new AbortController() : null;
			var signal = controller ? controller.signal : undefined;
			var rows = [];
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
			// The bar only moves when a step has really finished on the server.
			var draw = function (done) {
				var value = rows.length ? Math.floor(done / rows.length * 100) : 0;
				if (fill) {
					fill.style.width = value + '%';
				}
				if (percent) {
					percent.textContent = value + '%';
				}
				if (track) {
					track.setAttribute('aria-valuenow', String(value));
				}
				rows.forEach(function (row, index) {
					var state = index < done ? 'done' : (index === done ? 'active' : 'pending');
					if (row.getAttribute('data-state') !== state) {
						row.setAttribute('data-state', state);
						if ('active' === state && list) {
							// Keep the active row in view inside the list without moving the page.
							list.scrollTop = Math.max(0, row.offsetTop - list.offsetTop - list.clientHeight / 2);
						}
					}
				});
				if (step && rows.length) {
					var current = Math.min(done + 1, rows.length);
					step.textContent = (settings.step || 'Step %1$s of %2$s').replace('%1$s', String(current)).replace('%2$s', String(rows.length)) + ': ' + rows[current - 1].querySelector('.amsec-scan-name').textContent;
				}
			};
			// Any failure falls back to the plain form post, which runs the whole scan in one request.
			var fallback = function () {
				form.setAttribute('data-amsec-fallback', '1');
				if (step) {
					step.textContent = settings.saving || 'Saving the results';
				}
				form.submit();
			};
			if (stop) {
				stop.onclick = function () {
					if (controller) {
						controller.abort();
					}
					// Nothing is saved until the last step, so the previous report stays.
					window.location.assign(window.location.href.split('#')[0]);
				};
			}
			post(form, { step: 'start' }, signal).then(function (data) {
				rows = list ? buildList(list, data.steps) : [];
				draw(0);
				var run = function (index) {
					return post(form, { step: String(index), token: data.token }, signal).then(function (result) {
						if (result.note && rows[index]) {
							var note = document.createElement('span');
							note.className = 'amsec-scan-note';
							note.textContent = ' · ' + result.note;
							rows[index].appendChild(note);
						}
						draw(index + 1);
						if (result.done) {
							window.location.assign(result.done);
							return null;
						}
						return run(index + 1);
					});
				};
				return run(0);
			}).catch(function (error) {
				if (!error || 'AbortError' !== error.name) {
					fallback();
				}
			});
		});
	});
}());
