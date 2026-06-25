import { setIcon } from "obsidian";

import type {
  AgentBridgeAskUserArgs,
  AgentBridgeAskUserOption,
  AgentBridgeAskUserResult,
} from "../../../plugin/agent-bridge";

const CARD_CLS = "vaultguard-chat-user-question";
const ANSWERED_CLS = "is-answered";
const CANCELLED_CLS = "is-cancelled";

export interface UserQuestionCard {
  root: HTMLElement;
  setAnswered(result: AgentBridgeAskUserResult): void;
  setCancelled(message: string): void;
}

export interface RenderUserQuestionHandlers {
  answer(result: AgentBridgeAskUserResult): void;
  cancel(): void;
}

export function renderUserQuestion(
  parent: HTMLElement,
  request: AgentBridgeAskUserArgs,
  handlers: RenderUserQuestionHandlers,
): UserQuestionCard {
  const root = parent.createDiv({ cls: CARD_CLS });
  const header = root.createDiv({ cls: `${CARD_CLS}-header` });
  const icon = header.createSpan({ cls: `${CARD_CLS}-icon` });
  setIcon(icon, "message-circle-question");
  header.createSpan({ cls: `${CARD_CLS}-title`, text: "Claude asks" });

  const body = root.createDiv({ cls: `${CARD_CLS}-body` });
  if (request.context) {
    body.createDiv({ cls: `${CARD_CLS}-context`, text: request.context });
  }
  body.createDiv({ cls: `${CARD_CLS}-question`, text: request.question });

  const controls = body.createDiv({ cls: `${CARD_CLS}-controls` });
  const answered = { value: false };

  const answer = (result: AgentBridgeAskUserResult): void => {
    if (answered.value) return;
    answered.value = true;
    handlers.answer(result);
  };

  for (const option of request.options ?? []) {
    controls.appendChild(renderOptionButton(option, () => answer(optionResult(option))));
  }

  const allowFreeform = request.allowFreeform !== false;
  let input: HTMLTextAreaElement | null = null;
  if (allowFreeform) {
    const freeform = body.createDiv({ cls: `${CARD_CLS}-freeform` });
    input = freeform.createEl("textarea", {
      cls: `${CARD_CLS}-input`,
      attr: {
        rows: "2",
        placeholder: request.placeholder || "Type an answer...",
      },
    });
    const submit = freeform.createEl("button", {
      cls: `${CARD_CLS}-submit mod-cta`,
      text: "Send answer",
    });
    submit.addEventListener("click", () => {
      const value = input?.value.trim() ?? "";
      if (!value) {
        input?.focus();
        return;
      }
      answer({ answer: value });
    });
    input.addEventListener("keydown", (evt) => {
      if (evt.key !== "Enter" || evt.shiftKey) return;
      evt.preventDefault();
      submit.click();
    });
  }

  const footer = root.createDiv({ cls: `${CARD_CLS}-footer` });
  const cancel = footer.createEl("button", { cls: `${CARD_CLS}-cancel`, text: "Cancel question" });
  cancel.addEventListener("click", () => {
    if (answered.value) return;
    answered.value = true;
    handlers.cancel();
  });

  const setAnswered = (result: AgentBridgeAskUserResult): void => {
    root.addClass(ANSWERED_CLS);
    controls.querySelectorAll("button").forEach((btn) => {
      (btn as HTMLButtonElement).disabled = true;
    });
    if (input) input.disabled = true;
    cancel.remove();
    footer.empty();
    footer.createDiv({
      cls: `${CARD_CLS}-answer`,
      text: `Answered: ${result.selectedOptionLabel ?? result.answer}`,
    });
  };

  const setCancelled = (message: string): void => {
    root.addClass(CANCELLED_CLS);
    controls.querySelectorAll("button").forEach((btn) => {
      (btn as HTMLButtonElement).disabled = true;
    });
    if (input) input.disabled = true;
    footer.empty();
    footer.createDiv({ cls: `${CARD_CLS}-answer`, text: message });
  };

  window.setTimeout(() => input?.focus(), 0);

  return { root, setAnswered, setCancelled };
}

function renderOptionButton(option: AgentBridgeAskUserOption, onClick: () => void): HTMLElement {
  const button = document.createElement("button");
  button.addClass(`${CARD_CLS}-option`);
  button.type = "button";
  button.createDiv({ cls: `${CARD_CLS}-option-label`, text: option.label });
  if (option.description) {
    button.createDiv({ cls: `${CARD_CLS}-option-desc`, text: option.description });
  }
  button.addEventListener("click", onClick);
  return button;
}

function optionResult(option: AgentBridgeAskUserOption): AgentBridgeAskUserResult {
  return {
    answer: option.value || option.label,
    selectedOptionId: option.id,
    selectedOptionLabel: option.label,
    selectedOptionValue: option.value,
  };
}
