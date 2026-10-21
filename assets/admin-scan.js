(function () {
	var settings = window.amsecScan || {};

	var row = function (tag, number, label) {
		var item = document.createElement(tag);
		var dot = document.createElement('span');
		var num = document.createElement('span');
		var name = document.createElement('span');
		dot.className = 'amsec-scan-dot';
		dot.setAttribute('aria-hidden', 'true');
		num.className = 'amsec-scan-num';
		num.textContent = number;
		name.className = 'amsec-scan-name';
		name.textContent = label;
		item.setAttribute('data-state', 'pending');
		item.appendChild(dot);
		item.appendChild(num);
		item.appendChild(name);
		return item;
	};

	// Categories A, B, C... each fold their steps 1, 2, 3; only the running category opens. Saving is the last row.
	var buildList = function (list, data) {
		var rows = [];
		var groups = [];
		list.textContent = '';
		data.groups.forEach(function (group, g) {
			var head = document.createElement('li');
			var toggle = row('button', String.fromCharCode(65 + g) + '.', group.name);
			var count = document.createElement('span');
			var items = document.createElement('ol');
			head.className = 'amsec-scan-group';
			head.setAttribute('data-state', 'pending');
			toggle.className = 'amsec-scan-toggle';
			toggle.type = 'button';
			toggle.setAttribute('aria-expanded', 'false');
			count.className = 'amsec-scan-count';
			items.className = 'amsec-scan-items';
			items.hidden = true;
			toggle.appendChild(count);
			head.appendChild(toggle);
			head.appendChild(items);
			list.appendChild(head);
			// Anyone can open a folded category to see its steps, or fold the running one.
			toggle.addEventListener('click', function () {
				items.hidden = !items.hidden;
				toggle.setAttribute('aria-expanded', items.hidden ? 'false' : 'true');
			});
			var first = rows.length;
			group.steps.forEach(function (label, i) {
				var item = row('li', String(i + 1) + '.', label);
				item.setAttribute('data-group', String(g));
				items.appendChild(item);
				rows.push(item);
			});
			groups.push({ head: head, toggle: toggle, items: items, count: count, first: first, size: group.steps.length, state: 'pending' });
		});
		var save = row('li', '', data.save);
		save.className = 'amsec-scan-group';
		list.appendChild(save);
		rows.push(save);
		return { rows: rows, groups: groups };
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
			var groups = [];
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
				rows.forEach(function (item, index) {
					item.setAttribute('data-state', index < done ? 'done' : (index === done ? 'active' : 'pending'));
				});
				var activeGroup = -1;
				groups.forEach(function (group, g) {
					var finished = Math.max(0, Math.min(group.size, done - group.first));
					var state = finished === group.size ? 'done' : (done >= group.first ? 'active' : 'pending');
					if (state !== group.state) {
						// Only a change of state opens or folds a category, so a manual click sticks until then.
						group.state = state;
						group.head.setAttribute('data-state', state);
						group.toggle.setAttribute('data-state', state);
						group.items.hidden = 'active' !== state;
						group.toggle.setAttribute('aria-expanded', group.items.hidden ? 'false' : 'true');
					}
					group.count.textContent = finished + '/' + group.size;
					if ('active' === state) {
						activeGroup = g;
					}
				});
				if (step && rows.length) {
					var current = rows[Math.min(done, rows.length - 1)];
					var group = groups[activeGroup];
					step.textContent = group
						? (settings.group || 'Category %1$s of %2$s').replace('%1$s', String.fromCharCode(65 + activeGroup)).replace('%2$s', String(groups.length)) + ' · ' + (settings.step || 'Step %1$s of %2$s').replace('%1$s', String(done - group.first + 1)).replace('%2$s', String(group.size)) + ': ' + current.querySelector('.amsec-scan-name').textContent
						: current.querySelector('.amsec-scan-name').textContent;
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
				var built = list ? buildList(list, data) : { rows: [], groups: [] };
				rows = built.rows;
				groups = built.groups;
				draw(0);
				var run = function (index) {
					var began = Date.now();
					return post(form, { step: String(index), token: data.token }, signal).then(function (result) {
						// Each step stays on screen for at least a second so people can read what is being checked.
						return new Promise(function (resolve) {
							window.setTimeout(function () {
								resolve(result);
							}, Math.max(0, 1000 - (Date.now() - began)));
						});
					}).then(function (result) {
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
