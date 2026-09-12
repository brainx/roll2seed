import {
  BIP39_WORDLIST,
  entropyToMnemonic,
  runCryptographicSelfTests,
  validateMnemonic,
  verifyWordlistIntegrity,
} from "./entropy/bip39";
import {
  firstAcceptedRollCount,
  optionForWords,
  sampleRolls,
  type DiceSample,
  type DieFace,
  type PhraseOption,
} from "./entropy/diceSampler";

type SecretStage = "locked" | "ready" | "visible" | "hidden" | "verification" | "verified" | "cleared";

function required<T extends Element>(selector: string): T {
  const element = document.querySelector<T>(selector);
  if (!element) {
    throw new Error(`Required interface element is missing: ${selector}`);
  }
  return element;
}

function all<T extends Element>(selector: string): T[] {
  return Array.from(document.querySelectorAll<T>(selector));
}

const elements = {
  fatalError: required<HTMLElement>("#fatal-error"),
  fatalErrorMessage: required<HTMLElement>("#fatal-error-message"),
  workspace: required<HTMLElement>("#workspace"),
  phraseOptions: all<HTMLButtonElement>(".phrase-option"),
  lengthHelp: required<HTMLElement>("#length-help"),
  lengthLockNote: required<HTMLElement>("#length-lock-note"),
  safetyChecks: all<HTMLInputElement>("[data-safety-check]"),
  inputLock: required<HTMLElement>("#input-lock"),
  dieButtons: all<HTMLButtonElement>(".die-button"),
  undoButton: required<HTMLButtonElement>("#undo-button"),
  reviewRollsButton: required<HTMLButtonElement>("#review-rolls-button"),
  clearRollsButton: required<HTMLButtonElement>("#clear-rolls-button"),
  rollAnnouncement: required<HTMLElement>("#roll-announcement"),
  progressCopy: required<HTMLElement>("#progress-copy"),
  progressTrack: required<HTMLProgressElement>("#progress-track"),
  progressScale: all<HTMLElement>(".progress-scale span"),
  ledgerEmpty: required<HTMLElement>("#ledger-empty"),
  rollList: required<HTMLOListElement>("#roll-list"),
  networkWarning: required<HTMLElement>("#network-warning"),
  networkWarningCopy: required<HTMLElement>("#network-warning-copy"),
  wordlistDot: required<HTMLElement>("#wordlist-dot"),
  wordlistStatus: required<HTMLElement>("#wordlist-status"),
  samplerDot: required<HTMLElement>("#sampler-dot"),
  samplerStatus: required<HTMLElement>("#sampler-status"),
  whyExtraButton: required<HTMLButtonElement>("#why-extra-button"),
  biasDetails: required<HTMLDetailsElement>("#bias-details"),
  resultLocked: required<HTMLElement>("#result-locked"),
  lockedResultCopy: required<HTMLElement>("#locked-result-copy"),
  resultReady: required<HTMLElement>("#result-ready"),
  resultSecret: required<HTMLElement>("#result-secret"),
  resultHidden: required<HTMLElement>("#result-hidden"),
  resultVerification: required<HTMLElement>("#result-verification"),
  resultVerified: required<HTMLElement>("#result-verified"),
  resultCleared: required<HTMLElement>("#result-cleared"),
  summaryRolls: required<HTMLElement>("#summary-rolls"),
  summaryBits: required<HTMLElement>("#summary-bits"),
  summaryFormat: required<HTMLElement>("#summary-format"),
  revealCheck: required<HTMLInputElement>("#reveal-check"),
  revealButton: required<HTMLButtonElement>("#reveal-button"),
  mnemonicList: required<HTMLOListElement>("#mnemonic-list"),
  hideTimer: required<HTMLElement>("#hide-timer"),
  keepVisibleButton: required<HTMLButtonElement>("#keep-visible-button"),
  verifyBackupButton: required<HTMLButtonElement>("#verify-backup-button"),
  hidePhraseButton: required<HTMLButtonElement>("#hide-phrase-button"),
  eraseSecretButton: required<HTMLButtonElement>("#erase-secret-button"),
  hiddenReason: required<HTMLElement>("#hidden-reason"),
  showPhraseButton: required<HTMLButtonElement>("#show-phrase-button"),
  verifyHiddenButton: required<HTMLButtonElement>("#verify-hidden-button"),
  eraseHiddenButton: required<HTMLButtonElement>("#erase-hidden-button"),
  verificationForm: required<HTMLFormElement>("#verification-form"),
  verificationFields: required<HTMLElement>("#verification-fields"),
  verificationFeedback: required<HTMLElement>("#verification-feedback"),
  pasteWarning: required<HTMLElement>("#paste-warning"),
  cancelVerificationButton: required<HTMLButtonElement>("#cancel-verification-button"),
  finishButton: required<HTMLButtonElement>("#finish-button"),
  compareButton: required<HTMLButtonElement>("#compare-button"),
  newSessionButton: required<HTMLButtonElement>("#new-session-button"),
  clearDialog: required<HTMLDialogElement>("#clear-dialog"),
  clearDialogCopy: required<HTMLElement>("#clear-dialog-copy"),
  keepRollsButton: required<HTMLButtonElement>("#keep-rolls-button"),
  confirmClearButton: required<HTMLButtonElement>("#confirm-clear-button"),
  reviewDialog: required<HTMLDialogElement>("#review-dialog"),
  reviewRevealCheck: required<HTMLInputElement>("#review-reveal-check"),
  revealRollsButton: required<HTMLButtonElement>("#reveal-rolls-button"),
  reviewSecretContent: required<HTMLElement>("#review-secret-content"),
  reviewHideTimer: required<HTMLElement>("#review-hide-timer"),
  keepReviewVisibleButton: required<HTMLButtonElement>("#keep-review-visible-button"),
  reviewRollGrid: required<HTMLOListElement>("#review-roll-grid"),
  reviewEditPanel: required<HTMLElement>("#review-edit-panel"),
  reviewEditTitle: required<HTMLElement>("#review-edit-title"),
  reviewFaceButtons: all<HTMLButtonElement>("[data-edit-face]"),
  reviewStatus: required<HTMLElement>("#review-status"),
  doneReviewButton: required<HTMLButtonElement>("#done-review-button"),
  eraseDialog: required<HTMLDialogElement>("#erase-dialog"),
  keepSessionButton: required<HTMLButtonElement>("#keep-session-button"),
  confirmEraseButton: required<HTMLButtonElement>("#confirm-erase-button"),
};

let selectedOption: PhraseOption = optionForWords(24);
let rolls: DieFace[] = [];
let currentSample: DiceSample = sampleRolls([], selectedOption.entropyBits);
let mnemonic: readonly string[] | null = null;
let stage: SecretStage = "locked";
let selfTestsPassed = false;
let fatalFailure = false;
let generationToken = 0;
let verificationPositions: number[] = [];
let hideTimerId: number | null = null;
let hideDeadline = 0;
let hiddenReason = "The phrase was hidden. It remains only in this tab’s active memory until you erase the session.";
let selectedReviewIndex: number | null = null;
let reviewTimerId: number | null = null;
let reviewDeadline = 0;
let reviewExposed = false;

function safetyReady(): boolean {
  return selfTestsPassed && elements.safetyChecks.every((checkbox) => checkbox.checked);
}

function inputEnabled(): boolean {
  return safetyReady() && !fatalFailure && currentSample.acceptedValue === null && stage !== "cleared";
}

function setStatusIndicator(dot: HTMLElement, label: HTMLElement, status: "passed" | "failed"): void {
  dot.classList.remove("is-passed", "is-failed");
  dot.classList.add(status === "passed" ? "is-passed" : "is-failed");
  label.textContent = status;
}

function showFatalFailure(message: string): void {
  fatalFailure = true;
  selfTestsPassed = false;
  stage = "locked";
  elements.fatalErrorMessage.textContent = message;
  elements.fatalError.hidden = false;
  elements.fatalError.focus();
  render();
}

function updateNetworkNotice(): void {
  if (navigator.onLine) {
    elements.networkWarning.classList.remove("is-offline");
    elements.networkWarningCopy.textContent =
      "Network appears available. Disconnect Wi-Fi and Ethernet before entering rolls.";
  } else {
    elements.networkWarning.classList.add("is-offline");
    elements.networkWarningCopy.textContent =
      "Device appears offline. Browser connectivity detection is not a security guarantee.";
  }
}

function updatePhraseOptions(): void {
  const locked = rolls.length > 0 || stage === "cleared";
  for (const button of elements.phraseOptions) {
    const words = Number(button.dataset.words);
    const selected = words === selectedOption.words;
    button.classList.toggle("is-selected", selected);
    button.setAttribute("aria-checked", String(selected));
    button.disabled = locked;
  }

  elements.lengthLockNote.textContent = locked ? "Clear rolls to change length" : "Locks after the first roll";
  elements.lengthHelp.textContent =
    `${selectedOption.words} words uses ${selectedOption.entropyBits} bits and needs at least ${selectedOption.minimumRolls} fair d6 rolls. ` +
    "Confirm the intended wallet accepts this phrase length before funding it.";
}

function updateRollControls(): void {
  const enabled = inputEnabled();
  for (const button of elements.dieButtons) {
    button.disabled = !enabled;
  }
  elements.undoButton.disabled = rolls.length === 0 || currentSample.acceptedValue !== null || stage === "cleared";
  elements.reviewRollsButton.disabled = rolls.length === 0 || stage === "cleared" || fatalFailure;
  elements.clearRollsButton.disabled = rolls.length === 0 || stage === "cleared";

  elements.inputLock.classList.toggle("is-ready", enabled);
  if (fatalFailure) {
    elements.inputLock.textContent = "Input locked because a required cryptographic self-check failed.";
  } else if (!selfTestsPassed) {
    elements.inputLock.textContent = "Input locked while the wordlist and sampler self-tests run.";
  } else if (!safetyReady()) {
    const remaining = elements.safetyChecks.filter((checkbox) => !checkbox.checked).length;
    elements.inputLock.textContent = `Complete ${remaining} remaining safety ${remaining === 1 ? "check" : "checks"} to unlock roll entry.`;
  } else if (currentSample.acceptedValue !== null) {
    elements.inputLock.textContent = "Uniform entropy accepted. Roll input is locked for this session.";
  } else if (rolls.length >= selectedOption.minimumRolls) {
    const extra = rolls.length - selectedOption.minimumRolls;
    elements.inputLock.textContent =
      `Rejection sampling is protecting against modulo bias. Roll the physical die once more` +
      (extra > 0 ? ` (${extra} extra ${extra === 1 ? "roll" : "rolls"} so far).` : ".");
  } else {
    elements.inputLock.textContent = "Roll input unlocked. Record every physical result exactly as shown.";
  }
}

function updateProgress(): void {
  const minimum = selectedOption.minimumRolls;
  const shownRolls = Math.min(rolls.length, minimum);
  elements.progressTrack.max = minimum;
  elements.progressTrack.value = shownRolls;
  elements.progressScale.forEach((label, index) => {
    label.textContent = String(Math.round((minimum * index) / (elements.progressScale.length - 1)));
  });

  if (currentSample.acceptedValue !== null) {
    elements.progressCopy.textContent = `${rolls.length} physical rolls · uniform sample accepted`;
  } else if (rolls.length >= minimum) {
    const extra = rolls.length - minimum;
    elements.progressCopy.textContent =
      extra === 0
        ? "Minimum reached · roll again to remove bias"
        : `Minimum reached · ${extra} extra ${extra === 1 ? "roll" : "rolls"} recorded · roll again`;
  } else {
    elements.progressCopy.textContent = `${rolls.length} of ${minimum} minimum rolls`;
  }
}

function updateRollLedger(): void {
  elements.rollList.replaceChildren();
  if (currentSample.acceptedValue !== null) {
    elements.ledgerEmpty.textContent =
      "Roll ledger concealed after acceptance. Use the guarded review flow only in a private setting.";
    elements.ledgerEmpty.hidden = false;
    elements.rollList.hidden = true;
    return;
  }

  elements.ledgerEmpty.textContent =
    "No rolls recorded. Repeated values are normal—record exactly what the physical die shows.";
  const visibleRolls = rolls.slice(-24);
  const firstVisibleIndex = rolls.length - visibleRolls.length;

  visibleRolls.forEach((face, visibleIndex) => {
    const item = document.createElement("li");
    const absoluteIndex = firstVisibleIndex + visibleIndex + 1;
    item.dataset.index = `#${absoluteIndex}`;
    item.textContent = String(face);
    item.setAttribute("aria-label", `Roll ${absoluteIndex}: ${face}`);
    if (absoluteIndex === rolls.length) {
      item.classList.add("is-last");
    }
    elements.rollList.append(item);
  });

  elements.ledgerEmpty.hidden = rolls.length > 0;
  elements.rollList.hidden = rolls.length === 0;
}

function hideAllResultStates(): void {
  for (const result of [
    elements.resultLocked,
    elements.resultReady,
    elements.resultSecret,
    elements.resultHidden,
    elements.resultVerification,
    elements.resultVerified,
    elements.resultCleared,
  ]) {
    result.hidden = true;
  }
}

function renderMnemonic(): void {
  elements.mnemonicList.replaceChildren();
  if (stage !== "visible" || !mnemonic) {
    return;
  }

  mnemonic.forEach((word, index) => {
    const item = document.createElement("li");
    item.setAttribute("aria-label", `Word ${index + 1}: ${word}`);

    const number = document.createElement("span");
    number.className = "word-number";
    number.textContent = String(index + 1).padStart(2, "0");

    const value = document.createElement("span");
    value.className = "word-value";
    value.textContent = word;

    item.append(number, value);
    elements.mnemonicList.append(item);
  });
}

function updateResult(): void {
  hideAllResultStates();
  renderMnemonic();

  if (stage === "cleared") {
    elements.resultCleared.hidden = false;
    return;
  }
  if (stage === "verification") {
    elements.resultVerification.hidden = false;
    return;
  }
  if (stage === "verified") {
    elements.resultVerified.hidden = false;
    return;
  }
  if (stage === "visible" && mnemonic) {
    elements.resultSecret.hidden = false;
    return;
  }
  if (stage === "hidden" && mnemonic) {
    elements.hiddenReason.textContent = hiddenReason;
    elements.resultHidden.hidden = false;
    return;
  }
  if (stage === "ready" && mnemonic) {
    elements.summaryRolls.textContent = String(rolls.length);
    elements.summaryBits.textContent = `${selectedOption.entropyBits} unbiased bits`;
    elements.summaryFormat.textContent = `${selectedOption.words}-word BIP39 English`;
    elements.revealButton.disabled = !elements.revealCheck.checked;
    elements.resultReady.hidden = false;
    return;
  }

  if (fatalFailure) {
    elements.lockedResultCopy.textContent =
      "Generation is blocked because a required cryptographic self-check failed. Clear the session and reload a verified build.";
    elements.resultLocked.hidden = false;
    return;
  }

  if (currentSample.acceptedValue !== null) {
    elements.lockedResultCopy.textContent =
      "Uniform entropy accepted. Verifying the checksum and preparing the recovery phrase…";
    elements.resultLocked.hidden = false;
    return;
  }

  const remaining = Math.max(0, selectedOption.minimumRolls - rolls.length);
  elements.lockedResultCopy.textContent =
    remaining > 0
      ? `Locked until at least ${selectedOption.minimumRolls} physical rolls are recorded for ${selectedOption.words} words. ${remaining} minimum ${remaining === 1 ? "roll" : "rolls"} remaining.`
      : "The minimum is complete. Rejection sampling needs another physical roll to avoid bias.";
  elements.resultLocked.hidden = false;
}

function render(): void {
  updatePhraseOptions();
  updateRollControls();
  updateProgress();
  updateRollLedger();
  updateResult();
}

function stopHideTimer(): void {
  if (hideTimerId !== null) {
    window.clearInterval(hideTimerId);
    hideTimerId = null;
  }
  hideDeadline = 0;
}

function updateHideTimerCopy(): void {
  const secondsRemaining = Math.max(0, Math.ceil((hideDeadline - Date.now()) / 1000));
  const minutes = Math.floor(secondsRemaining / 60);
  const seconds = secondsRemaining % 60;
  elements.hideTimer.textContent = `Hides in ${minutes}:${String(seconds).padStart(2, "0")}`;
  if (secondsRemaining === 0 && stage === "visible") {
    hidePhrase("The phrase hid automatically after two minutes. It remains only in active memory until erased.");
  }
}

function focusResultHeading(selector: string): void {
  if (document.hidden || elements.clearDialog.open || elements.reviewDialog.open || elements.eraseDialog.open) {
    return;
  }
  const heading = required<HTMLElement>(selector);
  heading.setAttribute("tabindex", "-1");
  heading.focus();
}

function hidePhrase(reason: string): void {
  if (!mnemonic) {
    return;
  }
  stopHideTimer();
  hiddenReason = reason;
  stage = "hidden";
  render();
  focusResultHeading("#result-hidden h2");
}

function startHideTimer(): void {
  stopHideTimer();
  hideDeadline = Date.now() + 120_000;
  updateHideTimerCopy();
  hideTimerId = window.setInterval(updateHideTimerCopy, 1000);
}

function revealPhrase(): void {
  if (!mnemonic || !elements.revealCheck.checked) {
    return;
  }
  stage = "visible";
  render();
  startHideTimer();
  focusResultHeading("#result-secret h2");
}

function showPhraseAgain(): void {
  if (!mnemonic) {
    return;
  }
  stage = "visible";
  render();
  startHideTimer();
  focusResultHeading("#result-secret h2");
}

function invalidateDerivedState(): void {
  generationToken += 1;
  stopHideTimer();
  mnemonic = null;
  verificationPositions = [];
  elements.verificationFields.replaceChildren();
  elements.verificationFeedback.textContent = "";
  elements.pasteWarning.hidden = true;
  elements.rollAnnouncement.textContent = "";
  clearReviewSecretDisplay();
  elements.revealCheck.checked = false;
  stage = "locked";
}

async function deriveIfReady(): Promise<void> {
  if (fatalFailure) {
    return;
  }
  currentSample = sampleRolls(rolls, selectedOption.entropyBits);
  if (currentSample.acceptedValue === null) {
    render();
    return;
  }

  const token = ++generationToken;
  render();

  try {
    const candidate = await entropyToMnemonic(currentSample.acceptedValue, selectedOption.entropyBits);
    const valid = await validateMnemonic(candidate);
    if (token !== generationToken) {
      return;
    }
    if (!valid) {
      throw new Error("Generated BIP39 checksum did not validate");
    }
    mnemonic = candidate;
    stage = "ready";
    render();
    focusResultHeading("#result-ready h2");
  } catch {
    if (token === generationToken) {
      invalidateDerivedState();
      showFatalFailure("A required generation self-check failed. Clear this session and use a verified build.");
    }
  }
}

function flashDieButton(face: DieFace): void {
  const button = elements.dieButtons.find((candidate) => Number(candidate.dataset.face) === face);
  if (!button) {
    return;
  }
  button.classList.add("is-pressed");
  window.setTimeout(() => button.classList.remove("is-pressed"), 120);
}

function recordRoll(face: DieFace): void {
  if (!inputEnabled()) {
    return;
  }
  rolls.push(face);
  flashDieButton(face);
  elements.rollAnnouncement.textContent = `Recorded roll ${rolls.length}: face ${face}.`;
  void deriveIfReady();
}

function undoRoll(): void {
  if (rolls.length === 0 || currentSample.acceptedValue !== null) {
    return;
  }
  invalidateDerivedState();
  const removedAt = rolls.length;
  const removedFace = rolls.pop();
  currentSample = sampleRolls(rolls, selectedOption.entropyBits);
  elements.rollAnnouncement.textContent = `Removed roll ${removedAt}: face ${removedFace}.`;
  render();
}

function buildReviewRollGrid(): void {
  elements.reviewRollGrid.replaceChildren();
  rolls.forEach((face, index) => {
    const item = document.createElement("li");
    const button = document.createElement("button");
    const number = document.createElement("span");
    const value = document.createElement("strong");

    button.type = "button";
    button.dataset.rollIndex = String(index);
    button.setAttribute("aria-label", `Review roll ${index + 1}, recorded as ${face}`);
    button.setAttribute("aria-pressed", String(selectedReviewIndex === index));
    button.classList.toggle("is-selected", selectedReviewIndex === index);
    number.textContent = `#${index + 1}`;
    value.textContent = String(face);
    button.append(number, value);
    button.addEventListener("click", () => {
      selectedReviewIndex = index;
      for (const candidate of all<HTMLButtonElement>("#review-roll-grid button")) {
        const selected = Number(candidate.dataset.rollIndex) === index;
        candidate.classList.toggle("is-selected", selected);
        candidate.setAttribute("aria-pressed", String(selected));
      }
      elements.reviewEditTitle.textContent = `Correct roll #${index + 1}, currently ${face}`;
      elements.reviewEditPanel.hidden = false;
      elements.reviewStatus.textContent = "Choose the face shown on your paper tally, or select another roll.";
      for (const faceButton of elements.reviewFaceButtons) {
        faceButton.setAttribute(
          "aria-label",
          `Set roll ${index + 1} to face ${faceButton.dataset.editFace}`,
        );
      }
      elements.reviewFaceButtons[face - 1]?.focus();
    });

    item.append(button);
    elements.reviewRollGrid.append(item);
  });
}

function stopReviewTimer(): void {
  if (reviewTimerId !== null) {
    window.clearInterval(reviewTimerId);
    reviewTimerId = null;
  }
  reviewDeadline = 0;
}

function clearReviewSecretDisplay(): void {
  stopReviewTimer();
  reviewExposed = false;
  selectedReviewIndex = null;
  elements.reviewRollGrid.replaceChildren();
  elements.reviewEditPanel.hidden = true;
  elements.reviewSecretContent.hidden = true;
  elements.reviewRevealCheck.checked = false;
  elements.revealRollsButton.disabled = true;
  for (const faceButton of elements.reviewFaceButtons) {
    faceButton.setAttribute("aria-label", `Replacement face ${faceButton.dataset.editFace}`);
  }
  elements.reviewHideTimer.textContent = "Closes in 2:00";
  elements.reviewStatus.textContent =
    "Your paper tally is secret too. Destroy it after the recovery phrase is safely backed up.";
}

function closeReviewDialog(): void {
  if (elements.reviewDialog.open) {
    elements.reviewDialog.close();
  }
  clearReviewSecretDisplay();
}

function updateReviewTimer(): void {
  const secondsRemaining = Math.max(0, Math.ceil((reviewDeadline - Date.now()) / 1000));
  const minutes = Math.floor(secondsRemaining / 60);
  const seconds = secondsRemaining % 60;
  elements.reviewHideTimer.textContent = `Closes in ${minutes}:${String(seconds).padStart(2, "0")}`;
  if (secondsRemaining === 0) {
    elements.rollAnnouncement.textContent = "The complete roll tally was concealed after two minutes.";
    closeReviewDialog();
  }
}

function startReviewTimer(): void {
  stopReviewTimer();
  reviewDeadline = Date.now() + 120_000;
  updateReviewTimer();
  reviewTimerId = window.setInterval(updateReviewTimer, 1000);
}

function revealReviewRolls(): void {
  if (
    fatalFailure ||
    !elements.reviewDialog.open ||
    !elements.reviewRevealCheck.checked ||
    rolls.length === 0
  ) {
    return;
  }
  reviewExposed = true;
  buildReviewRollGrid();
  elements.reviewSecretContent.hidden = false;
  elements.reviewStatus.textContent =
    "Repeated faces and long runs are valid. Correct only a mismatch with your separate paper tally.";
  startReviewTimer();
  elements.reviewRollGrid.querySelector<HTMLButtonElement>("button")?.focus();
}

function openReviewDialog(): void {
  if (fatalFailure || rolls.length === 0 || stage === "cleared") {
    return;
  }
  stopHideTimer();
  if (stage === "visible") {
    hiddenReason = "The phrase was hidden while you review the recorded rolls.";
    stage = "hidden";
    render();
  }
  clearReviewSecretDisplay();
  elements.reviewDialog.showModal();
}

function correctSelectedRoll(face: DieFace): void {
  if (
    fatalFailure ||
    !reviewExposed ||
    !elements.reviewDialog.open ||
    selectedReviewIndex === null ||
    selectedReviewIndex < 0 ||
    selectedReviewIndex >= rolls.length
  ) {
    return;
  }

  const index = selectedReviewIndex;
  const previousFace = rolls[index] as DieFace;
  if (previousFace === face) {
    elements.reviewStatus.textContent = `Roll #${index + 1} is already recorded as ${face}. No change made.`;
    return;
  }

  invalidateDerivedState();
  rolls[index] = face;
  const acceptedAt = firstAcceptedRollCount(rolls, selectedOption.entropyBits);
  let removedTrailing = 0;
  if (acceptedAt !== null && acceptedAt < rolls.length) {
    const originalRolls = rolls;
    rolls = originalRolls.slice(0, acceptedAt);
    removedTrailing = originalRolls.length - acceptedAt;
    originalRolls.fill(0 as DieFace);
  }
  currentSample = sampleRolls(rolls, selectedOption.entropyBits);
  elements.reviewDialog.close();
  selectedReviewIndex = null;
  elements.rollAnnouncement.textContent =
    `Corrected roll ${index + 1} from face ${previousFace} to face ${face}.` +
    (removedTrailing > 0
      ? ` The corrected sequence accepted earlier, so ${removedTrailing} now-unused trailing ${removedTrailing === 1 ? "roll was" : "rolls were"} removed.`
      : " The entropy result was recomputed.");
  render();
  void deriveIfReady();
}

function bestEffortReleaseActiveState(showClearedState: boolean): void {
  generationToken += 1;
  stopHideTimer();
  closeReviewDialog();
  clearReviewSecretDisplay();
  rolls.fill(0 as DieFace);
  rolls = [];
  mnemonic = null;
  verificationPositions.fill(0);
  verificationPositions = [];
  elements.mnemonicList.replaceChildren();
  for (const input of all<HTMLInputElement>("#verification-fields input")) {
    input.value = "";
  }
  elements.verificationFields.replaceChildren();
  elements.verificationFeedback.textContent = "";
  elements.pasteWarning.hidden = true;
  elements.rollAnnouncement.textContent = "";
  elements.revealCheck.checked = false;
  currentSample = sampleRolls([], selectedOption.entropyBits);
  stage = showClearedState ? "cleared" : "locked";
  render();
}

function openClearDialog(): void {
  stopHideTimer();
  if (stage === "visible") {
    hiddenReason = "The phrase was hidden while you confirm whether to clear the recorded rolls.";
    stage = "hidden";
    render();
  }
  elements.clearDialogCopy.textContent =
    `Clear all ${rolls.length} recorded ${rolls.length === 1 ? "roll" : "rolls"}? ` +
    "This removes the active sequence and any derived phrase from the page.";
  elements.clearDialog.showModal();
}

function openEraseDialog(): void {
  stopHideTimer();
  if (stage === "visible") {
    hiddenReason = "The phrase was hidden while you confirm whether to erase the session.";
    stage = "hidden";
    render();
  }
  elements.eraseDialog.showModal();
}

function randomIndex(bound: number): number {
  if (!Number.isInteger(bound) || bound < 1) {
    throw new RangeError("Random selection bound must be a positive integer");
  }
  const range = 0x1_0000_0000;
  const usable = Math.floor(range / bound) * bound;
  const sample = new Uint32Array(1);
  do {
    crypto.getRandomValues(sample);
  } while ((sample[0] as number) >= usable);
  const result = (sample[0] as number) % bound;
  sample.fill(0);
  return result;
}

function chooseVerificationPositions(wordCount: number): number[] {
  const chosen = new Set<number>();
  for (let quarter = 0; quarter < 4; quarter += 1) {
    const start = Math.floor((quarter * wordCount) / 4);
    const end = Math.floor(((quarter + 1) * wordCount) / 4);
    chosen.add(start + randomIndex(end - start));
  }
  while (chosen.size < Math.min(6, wordCount)) {
    chosen.add(randomIndex(wordCount));
  }
  return Array.from(chosen).sort((left, right) => left - right);
}

function buildVerificationFields(): void {
  elements.verificationFields.replaceChildren();
  for (const position of verificationPositions) {
    const wrapper = document.createElement("div");
    wrapper.className = "verification-field";

    const label = document.createElement("label");
    const inputId = `verification-word-${position + 1}`;
    label.htmlFor = inputId;
    label.textContent = `Word #${position + 1}`;

    const input = document.createElement("input");
    input.id = inputId;
    input.name = `word-${position + 1}`;
    input.type = "text";
    input.autocomplete = "off";
    input.autocapitalize = "none";
    input.spellcheck = false;
    input.maxLength = 12;
    input.dataset.position = String(position);
    input.setAttribute("aria-label", `Enter word ${position + 1} from your paper backup`);
    input.addEventListener("paste", () => {
      elements.pasteWarning.hidden = false;
    });

    wrapper.append(label, input);
    elements.verificationFields.append(wrapper);
  }
}

function startVerification(): void {
  if (!mnemonic) {
    return;
  }
  stopHideTimer();
  verificationPositions = chooseVerificationPositions(mnemonic.length);
  stage = "verification";
  buildVerificationFields();
  render();
  focusResultHeading("#result-verification h2");
}

function verifyPaperBackup(event: SubmitEvent): void {
  event.preventDefault();
  if (!mnemonic || verificationPositions.length === 0) {
    return;
  }

  elements.verificationFeedback.textContent = "";
  elements.verificationFeedback.classList.remove("is-error");
  let firstInvalid: HTMLInputElement | null = null;
  let errorMessage = "";

  for (const input of all<HTMLInputElement>("#verification-fields input")) {
    input.setAttribute("aria-invalid", "false");
    const position = Number(input.dataset.position);
    const value = input.value.trim().toLowerCase();
    if (!value) {
      firstInvalid ??= input;
      input.setAttribute("aria-invalid", "true");
      errorMessage ||= `Enter word ${position + 1} from your paper backup.`;
    } else if (!BIP39_WORDLIST.includes(value)) {
      firstInvalid ??= input;
      input.setAttribute("aria-invalid", "true");
      errorMessage ||= `“${value}” is not in the BIP39 English wordlist. Check its spelling.`;
    } else if (value !== mnemonic[position]) {
      firstInvalid ??= input;
      input.setAttribute("aria-invalid", "true");
      errorMessage ||= `Word ${position + 1} does not match. Check your paper backup.`;
    }
  }

  if (firstInvalid) {
    elements.verificationFeedback.textContent = errorMessage;
    elements.verificationFeedback.classList.add("is-error");
    firstInvalid.focus();
    return;
  }

  for (const input of all<HTMLInputElement>("#verification-fields input")) {
    input.value = "";
  }
  elements.verificationFields.replaceChildren();
  verificationPositions.fill(0);
  verificationPositions = [];
  elements.pasteWarning.hidden = true;
  stage = "verified";
  render();
  focusResultHeading("#result-verified h2");
}

function resetForNewSession(): void {
  for (const checkbox of elements.safetyChecks) {
    checkbox.checked = false;
  }
  stage = "locked";
  render();
  required<HTMLElement>("#safety-title").setAttribute("tabindex", "-1");
  required<HTMLElement>("#safety-title").focus();
}

function runSamplerBoundarySelfTest(): boolean {
  const rejectedBoundary = Array.from(
    "61262262611466652634263242642635642166662444332123",
    (digit) => Number(digit),
  );
  const rejected = sampleRolls(rejectedBoundary, 128);
  const recycled = sampleRolls([...rejectedBoundary, 1], 128);
  return !rejected.accepted && recycled.accepted && recycled.acceptedValue === 0n;
}

async function initializeSecurityChecks(): Promise<void> {
  if (!window.isSecureContext || !globalThis.crypto?.subtle) {
    setStatusIndicator(elements.wordlistDot, elements.wordlistStatus, "failed");
    setStatusIndicator(elements.samplerDot, elements.samplerStatus, "failed");
    showFatalFailure(
      "This browser context does not provide the required secure Web Crypto SHA-256 functions. Use the local server on 127.0.0.1.",
    );
    return;
  }

  try {
    if (!(await verifyWordlistIntegrity())) {
      throw new Error("Wordlist integrity failed");
    }
    setStatusIndicator(elements.wordlistDot, elements.wordlistStatus, "passed");

    await runCryptographicSelfTests();
    if (!runSamplerBoundarySelfTest()) {
      throw new Error("Sampler boundary test failed");
    }
    setStatusIndicator(elements.samplerDot, elements.samplerStatus, "passed");
    selfTestsPassed = true;
    render();
  } catch {
    setStatusIndicator(elements.samplerDot, elements.samplerStatus, "failed");
    showFatalFailure("The embedded wordlist, sampler, or BIP39 checksum self-test failed.");
  }
}

for (const button of elements.phraseOptions) {
  button.addEventListener("click", () => {
    if (rolls.length > 0) {
      return;
    }
    selectedOption = optionForWords(Number(button.dataset.words));
    invalidateDerivedState();
    currentSample = sampleRolls([], selectedOption.entropyBits);
    render();
  });
}

for (const checkbox of elements.safetyChecks) {
  checkbox.addEventListener("change", render);
}

for (const button of elements.dieButtons) {
  button.addEventListener("click", () => recordRoll(Number(button.dataset.face) as DieFace));
}

elements.undoButton.addEventListener("click", undoRoll);
elements.reviewRollsButton.addEventListener("click", openReviewDialog);
elements.clearRollsButton.addEventListener("click", openClearDialog);
elements.keepRollsButton.addEventListener("click", () => elements.clearDialog.close());
elements.confirmClearButton.addEventListener("click", () => {
  elements.clearDialog.close();
  bestEffortReleaseActiveState(false);
});
elements.reviewRevealCheck.addEventListener("change", () => {
  elements.revealRollsButton.disabled = !elements.reviewRevealCheck.checked;
});
elements.revealRollsButton.addEventListener("click", revealReviewRolls);
elements.keepReviewVisibleButton.addEventListener("click", startReviewTimer);
elements.doneReviewButton.addEventListener("click", closeReviewDialog);
elements.reviewDialog.addEventListener("close", clearReviewSecretDisplay);
for (const button of elements.reviewFaceButtons) {
  button.addEventListener("click", () => correctSelectedRoll(Number(button.dataset.editFace) as DieFace));
}

elements.revealCheck.addEventListener("change", render);
elements.revealButton.addEventListener("click", revealPhrase);
elements.keepVisibleButton.addEventListener("click", startHideTimer);
elements.hidePhraseButton.addEventListener("click", () =>
  hidePhrase("You hid the phrase. It remains only in this tab’s active memory until you erase the session."),
);
elements.showPhraseButton.addEventListener("click", showPhraseAgain);
elements.verifyBackupButton.addEventListener("click", startVerification);
elements.verifyHiddenButton.addEventListener("click", startVerification);
elements.verificationForm.addEventListener("submit", verifyPaperBackup);
elements.cancelVerificationButton.addEventListener("click", () => {
  verificationPositions.fill(0);
  verificationPositions = [];
  elements.verificationFields.replaceChildren();
  hiddenReason = "The backup check was cancelled. The phrase remains hidden in active memory.";
  stage = "hidden";
  render();
  focusResultHeading("#result-hidden h2");
});

for (const button of [elements.eraseSecretButton, elements.eraseHiddenButton, elements.finishButton]) {
  button.addEventListener("click", openEraseDialog);
}

elements.keepSessionButton.addEventListener("click", () => elements.eraseDialog.close());
elements.confirmEraseButton.addEventListener("click", () => {
  elements.eraseDialog.close();
  bestEffortReleaseActiveState(true);
});
elements.compareButton.addEventListener("click", showPhraseAgain);
elements.newSessionButton.addEventListener("click", resetForNewSession);

elements.whyExtraButton.addEventListener("click", () => {
  elements.biasDetails.open = true;
  elements.biasDetails.scrollIntoView({ behavior: "smooth", block: "center" });
  const summary = elements.biasDetails.querySelector<HTMLElement>("summary");
  summary?.focus();
});

document.addEventListener("keydown", (event) => {
  if (event.repeat || event.altKey) {
    return;
  }
  const target = event.target;
  if (
    (target instanceof HTMLInputElement && target.type !== "checkbox") ||
    target instanceof HTMLTextAreaElement
  ) {
    return;
  }
  if (elements.clearDialog.open || elements.reviewDialog.open || elements.eraseDialog.open) {
    return;
  }

  if (/^[1-6]$/.test(event.key) && !event.metaKey && !event.ctrlKey) {
    event.preventDefault();
    recordRoll(Number(event.key) as DieFace);
    return;
  }

  if (event.key === "Backspace" || ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "z")) {
    event.preventDefault();
    undoRoll();
  }
});

document.addEventListener("visibilitychange", () => {
  if (document.hidden) {
    if (elements.reviewDialog.open) {
      elements.rollAnnouncement.textContent = "The complete roll tally was concealed because this tab lost visibility.";
      closeReviewDialog();
    }
    if (stage === "visible") {
      hidePhrase("The phrase was hidden because this tab lost visibility. It remains in active memory until erased.");
    }
  }
});

window.addEventListener("online", updateNetworkNotice);
window.addEventListener("offline", updateNetworkNotice);
window.addEventListener("blur", () => {
  if (elements.reviewDialog.open && reviewExposed) {
    elements.rollAnnouncement.textContent = "The complete roll tally was concealed because the window lost focus.";
    closeReviewDialog();
  }
  if (stage === "visible") {
    hidePhrase("The phrase was hidden because the window lost focus. It remains in active memory until erased.");
  }
});
window.addEventListener("beforeunload", (event) => {
  if (rolls.length === 0 || stage === "cleared") {
    return;
  }
  if (elements.reviewDialog.open) {
    elements.rollAnnouncement.textContent = "The complete roll tally was concealed before leaving this page.";
    closeReviewDialog();
  }
  if (stage === "visible") {
    hidePhrase("The phrase was hidden while the browser asks whether to leave this page.");
  }
  event.preventDefault();
  event.returnValue = "";
});
window.addEventListener("pagehide", () => bestEffortReleaseActiveState(false));

if (elements.progressScale.length !== 6 || elements.reviewFaceButtons.length !== 6) {
  throw new Error("Required progress or roll-correction controls are missing");
}

updateNetworkNotice();
render();
void initializeSecurityChecks();
