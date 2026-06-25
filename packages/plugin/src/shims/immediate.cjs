"use strict";

let draining = false;
let queue = [];

function scheduleDrain() {
  if (typeof queueMicrotask === "function") {
    queueMicrotask(drain);
    return;
  }
  Promise.resolve().then(drain, function () {
    setTimeout(drain, 0);
  });
}

function drain() {
  draining = true;
  try {
    while (queue.length > 0) {
      const current = queue;
      queue = [];
      for (let i = 0; i < current.length; i++) {
        current[i]();
      }
    }
  } finally {
    draining = false;
  }
}

module.exports = function immediate(task) {
  if (typeof task !== "function") {
    throw new TypeError("immediate task must be a function");
  }
  queue.push(task);
  if (queue.length === 1 && !draining) {
    scheduleDrain();
  }
};
