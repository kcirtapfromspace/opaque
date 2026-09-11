/* Illustrative state only. No provider, credential, or product API calls. */
(function () {
  "use strict";
  var scene = document.querySelector(".op-task-scene");
  if (!scene) return;
  var motion = window.matchMedia("(prefers-reduced-motion: reduce)");
  var choice = "allowed", step = -1, elapsed = 0, previous = null, frame = 0;
  var paused = false, visible = true, complete = false;
  var pause = scene.querySelector(".op-task-pause");
  var phaseDuration = 1800;
  var routes = Array.from(scene.querySelectorAll(".op-flow-route"));
  var budget = scene.querySelector(".op-flow-budget");
  var oldBudget = scene.querySelector(".op-flow-budget-old");
  function clamp(value) { return Math.max(0, Math.min(1, value)); }
  function ease(value) { var t = clamp(value); return t * t * (3 - 2 * t); }
  function drawFlow(progress) {
    var phase = plans[choice][step][0], p = clamp(progress);
    var rejected = choice === "changed" || choice === "production";
    routes.forEach(function (route) {
      var name = route.dataset.flow, active = false, done = false, t = p, state = "idle";
      if (name === "request") {
        active = phase === "request" || phase === "retry";
        done = step > 0;
        if ((rejected && step > 0) || phase === "retry") state = "blocked";
        if (phase === "retry") t = p / .6;
      } else if (name === "review") {
        active = !rejected && phase === "review";
        done = !rejected && step > 1;
      } else if (name === "dispatch") {
        active = phase === "dispatch";
        done = !rejected && step > 4;
      } else if (name === "response") {
        active = phase === "result" && p < .55;
        t = p / .55;
        done = phase === "result" && p >= .55;
        if (phase === "unknown" || phase === "retry") state = "unknown";
      } else if (name === "status") {
        active = (phase === "result" && p >= .55) || phase === "unknown" || (rejected && step === 1);
        t = phase === "result" ? (p - .55) / .45 : p;
        done = (phase === "result" && p === 1) || phase === "retry" || (rejected && step === 2);
        if (rejected && step > 0) state = "blocked";
      }
      if (state === "idle" && done) state = "complete";
      route.dataset.state = state;
      var trace = route.querySelector(".op-flow-trace");
      trace.style.strokeDashoffset = String(.15 - ease(t) * 1.15);
      trace.style.opacity = active && t < 1 && p < 1 && !motion.matches ? "1" : "0";
    });
    var flip = phase === "consume" ? ease(p * 2) : 1;
    budget.style.transform = "translateY(" + ((1 - flip) * 100) + "%)";
    oldBudget.style.transform = "translateY(" + (-flip * 100) + "%)";
    oldBudget.style.opacity = phase === "consume" ? "1" : "0";
  }
  var plans = {
    allowed: [
      ["request", "01 / PLAN", "An agent proposes a release.", "One repository, workflow, image, and staging destination. The task has a ten-minute lifetime."],
      ["review", "02 / REVIEW", "Approval belongs to this task.", "A human reviews the complete manifest. Approval cannot carry over to changed scope."],
      ["checks", "03 / CHECK", "Authority is checked again.", "The task must still satisfy scope, current policy and identity, expiry, and revocation checks."],
      ["consume", "04 / CONSUME", "One attempt becomes zero.", "Opaque durably consumes the allowance before dispatch. An error cannot replenish it."],
      ["dispatch", "05 / DISPATCH", "The reviewed workflow is called.", "One dispatch leaves the broker. The credential stays with Opaque."],
      ["result", "06 / OBSERVE", "Inspect the workflow result.", "Dispatch acceptance does not prove deployment success. The task record preserves what was observed."]
    ],
    changed: [
      ["request", "01 / CHANGE", "The agent requests a different build.", "The task was approved for one build. The agent now asks to release another."],
      ["blocked", "02 / SCOPE", "That approval does not cover this build.", "Approval is bound to the reviewed task. It cannot authorize the replacement build."],
      ["blocked", "03 / STOP", "Changed task. New review.", "Opaque blocks the changed request. Submit the new build as a new task for review."]
    ],
    production: [
      ["request", "01 / CHANGE", "Production is requested.", "The agent proposes a production destination instead of the permitted staging target."],
      ["blocked", "02 / SCOPE", "Outside this operation.", "This release operation permits staging only. Human approval cannot expand it to production."],
      ["blocked", "03 / STOP", "No production dispatch.", "The production request is rejected by this operation before dispatch."]
    ],
    retry: [
      ["request", "01 / PLAN", "One staging task is requested.", "The task pins the release scope and a ten-minute lifetime."],
      ["review", "02 / REVIEW", "The exact task is approved.", "Approval is bound to the reviewed manifest, with at most one dispatch attempt."],
      ["checks", "03 / CHECK", "Current authority permits it.", "Opaque rechecks the task's policy, identity, scope, deadline, and revocation state."],
      ["consume", "04 / CONSUME", "The allowance is consumed.", "The single attempt is charged before the provider call. It is not refundable."],
      ["dispatch", "05 / DISPATCH", "The dispatch begins.", "Opaque calls the staging workflow. The connection ends before a result is confirmed."],
      ["unknown", "06 / UNKNOWN", "The outcome is unknown.", "The attempt stays consumed. A timeout does not establish whether the provider acted."],
      ["retry", "07 / RETRY BLOCKED", "Zero means no second attempt.", "Opaque blocks another dispatch on this task. Reconciliation reads evidence without repeating the call."]
    ]
  };
  function text(selector, value) { scene.querySelector(selector).textContent = value; }
  function render(next) {
    if (next === step) return;
    step = next;
    var entry = plans[choice][step], phase = entry[0];
    var rejected = choice === "changed" || choice === "production";
    var consumed = !rejected && step >= 3;
    scene.dataset.phase = phase;
    scene.dataset.consumed = String(consumed);
    text(".op-task-step", entry[1]);
    text(".op-task-state", entry[2]);
    text(".op-task-description", entry[3]);
    text(".op-task-seal", phase === "request" ? "Proposed" : rejected ? "Not covered" : "Approved");
    text(".op-task-binding > span", phase === "request" ? "Scope prepared for review" : rejected ? "Original approval does not apply" : "Approval bound to this task");
    ["image", "destination"].forEach(function (field) {
      var el = scene.querySelector(".op-task-" + field);
      var changed = step > 0 && ((field === "image" && choice === "changed") || (field === "destination" && choice === "production"));
      el.classList.toggle("is-changed", changed);
      el.querySelector(".op-task-proposed").hidden = !changed;
    });
    text('[data-check="scope"]', rejected && step > 0 ? "Rejected" : !rejected && step >= 2 ? "Matched" : "Pending");
    text('[data-check="authority"]', !rejected && step >= 2 ? "Current" : "—");
    text('[data-check="deadline"]', !rejected && step >= 2 ? "Valid" : "—");
    text(".op-task-charge", consumed ? "Consumed" : rejected ? "No dispatch" : "Available");
    text(".op-task-one", rejected ? "—" : "1");
    scene.querySelector(".op-task-retry").hidden = phase !== "retry";
    text(".op-task-wire-label", rejected ? "no dispatch" : step < 4 ? "awaiting authority" : "one dispatch");
    var result = rejected ? "Not dispatched" : phase === "result" ? "Dispatch accepted" : ["unknown", "retry"].includes(phase) ? "Outcome unknown" : phase === "dispatch" ? "Dispatching" : "Not dispatched";
    text(".op-task-result__state", result);
    text(".op-task-result__mark", rejected ? "×" : ["unknown", "retry"].includes(phase) ? "?" : phase === "result" ? "↗" : "—");
    text(".op-flow-budget", rejected ? "—" : consumed ? "0" : "1");
    text(".op-flow-charge", consumed ? "Consumed" : rejected ? "Not authorized" : "Available");
    text(".op-flow-decision", rejected && step > 0 ? "Scope rejected" : phase === "retry" ? "Retry blocked" : step >= 2 ? "Checks passed" : phase === "review" ? "Awaiting approval" : "Awaiting task");
    text(".op-flow-review-state", choice === "production" ? "Cannot expand scope" : rejected ? "New review required" : step >= 2 ? "Exact task approved" : "Review exact task");
    text(".op-flow-agent-state", rejected && step > 0 ? "Request rejected" : phase === "retry" ? "Retry rejected" : ["result", "unknown"].includes(phase) ? "Inspect task status" : "Propose a task");
    text(".op-flow-provider-state", result);
    text(".op-flow-scope-value", choice === "production" && step > 0 ? "production blocked" : choice === "changed" && step > 0 ? "build changed" : "staging");
  }
  function sync() {
    window.cancelAnimationFrame(frame);
    previous = null;
    var running = !paused && !complete && visible && !document.hidden && !motion.matches;
    scene.classList.toggle("is-paused", !running);
    pause.disabled = motion.matches || complete;
    pause.textContent = complete ? "Finished" : paused ? "Play" : "Pause";
    pause.setAttribute("aria-label", paused ? "Resume task illustration" : "Pause task illustration");
    pause.setAttribute("aria-pressed", String(paused));
    if (running) frame = window.requestAnimationFrame(tick);
  }
  function tick(now) {
    if (previous !== null) elapsed += now - previous;
    previous = now;
    var last = plans[choice].length - 1;
    render(Math.min(last, Math.floor(elapsed / phaseDuration)));
    drawFlow(step === last ? Math.min(1, (elapsed - last * phaseDuration) / phaseDuration) : (elapsed % phaseDuration) / phaseDuration);
    scene.style.setProperty("--task-progress", String(Math.min(1, elapsed / ((last + 1) * phaseDuration))));
    if (elapsed >= (last + 1) * phaseDuration) { complete = true; sync(); }
    else frame = window.requestAnimationFrame(tick);
  }
  function restart() {
    elapsed = 0; previous = null; step = -1; complete = motion.matches;
    scene.dataset.case = choice;
    scene.style.setProperty("--task-progress", motion.matches ? "1" : "0");
    render(motion.matches ? plans[choice].length - 1 : 0);
    drawFlow(motion.matches ? 1 : 0);
    sync();
  }
  scene.querySelectorAll(".op-task-cases button").forEach(function (button) {
    button.addEventListener("click", function () {
      choice = button.dataset.case;
      scene.querySelectorAll(".op-task-cases button").forEach(function (item) { item.setAttribute("aria-pressed", String(item === button)); });
      restart();
    });
  });
  pause.addEventListener("click", function () { paused = !paused; sync(); });
  scene.querySelector(".op-task-replay").addEventListener("click", function () { paused = false; restart(); });
  document.addEventListener("visibilitychange", sync);
  motion.addEventListener("change", restart);
  if ("IntersectionObserver" in window) new IntersectionObserver(function (entries) { visible = entries[0].isIntersecting; sync(); }, { threshold: .15 }).observe(scene);
  scene.querySelector(".op-task-cases").hidden = false;
  scene.querySelector(".op-task-controls").hidden = false;
  restart();
}());
