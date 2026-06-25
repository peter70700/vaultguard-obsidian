"use strict";

const root = typeof globalThis !== "undefined" ? globalThis : global;
let nextHandle = 1;
const tasks = new Map();

function run(handle) {
  const task = tasks.get(handle);
  if (!task) return;
  tasks.delete(handle);
  task.callback.apply(undefined, task.args);
}

function schedule(handle) {
  if (typeof queueMicrotask === "function") {
    queueMicrotask(function () {
      run(handle);
    });
    return;
  }
  setTimeout(run, 0, handle);
}

if (typeof root.setImmediate !== "function") {
  root.setImmediate = function setImmediate(callback) {
    if (typeof callback !== "function") {
      throw new TypeError("setImmediate callback must be a function");
    }
    const handle = nextHandle++;
    tasks.set(handle, {
      callback,
      args: Array.prototype.slice.call(arguments, 1),
    });
    schedule(handle);
    return handle;
  };
}

if (typeof root.clearImmediate !== "function") {
  root.clearImmediate = function clearImmediate(handle) {
    tasks.delete(handle);
  };
}

module.exports = root.setImmediate;
