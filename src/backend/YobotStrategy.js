import { Move } from "../game/Move.js";

const LETTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

const PREMIUM_LABELS = {
  D: "double word",
  M: "double word",
  T: "triple word",
  Q: "quad word",
  d: "double letter",
  t: "triple letter",
  q: "quad letter"
};

const DEFAULT_ENDPOINT = "https://api.openai.com/v1/chat/completions";

function coord(col, row) {
  const letter = LETTERS[col] || `C${col}`;
  return `${letter}${row + 1}`;
}

function premiumLabel(square) {
  if (!square)
    return undefined;
  return PREMIUM_LABELS[square.type];
}

function boardToAscii(board) {
  const rows = [];
  for (let row = 0; row < board.rows; row++) {
    let line = "";
    for (let col = 0; col < board.cols; col++) {
      const sq = board.at(col, row);
      line += (sq.tile && sq.tile.letter)
        ? sq.tile.letter.toUpperCase() : ".";
    }
    rows.push(line);
  }
  return rows.join("\n");
}

function describePremiumThreats(board, limit = 12) {
  const threats = [];
  board.forEachSquare(square => {
    if (!square || !square.isBoard || !square.isEmpty())
      return false;
    const label = premiumLabel(square);
    if (!label)
      return false;
    const weight =
          (square.wordScoreMultiplier || 1) * 10
          + (square.letterScoreMultiplier || 1);
    threats.push({
      coord: coord(square.col, square.row),
      label,
      weight
    });
    return false;
  });
  threats.sort((a, b) => b.weight - a.weight);
  return threats.slice(0, limit)
  .map(t => `${t.coord} (${t.label})`).join(", ") || "None";
}

function summarizePlacements(move, board) {
  const placements = move.placements || [];
  if (!placements.length)
    return "";
  const coords = placements.map(tile => {
    const grid = coord(tile.col, tile.row);
    const letter = tile.isBlank
      ? ((tile.letter && tile.letter.trim())
         ? tile.letter.toLowerCase()
         : "_")
      : tile.letter;
    const premium = premiumLabel(board.at(tile.col, tile.row));
    return `${grid}=${letter}${premium ? `[${premium}]` : ""}`;
  });
  return coords.join(", ");
}

function summarizeCandidate(move, idx, board) {
  const label = String.fromCharCode(65 + idx);
  const clone = new Move(move);
  const mainWords = (clone.words || [])
  .map(w => `${w.word} (${w.score})`).join(", ") || "none";
  const placements = summarizePlacements(clone, board);
  const horizontal = clone.placements && clone.placements.length > 1
    ? clone.placements.every(t => t.row === clone.placements[0].row)
    : true;
  const startTile = clone.placements && clone.placements.length
    ? clone.placements.reduce(
      (best, tile) => {
        if (!best)
          return tile;
        return horizontal
          ? (tile.col < best.col ? tile : best)
          : (tile.row < best.row ? tile : best);
      }, clone.placements[0])
    : undefined;
  const startCoord = startTile ? coord(startTile.col, startTile.row) : "N/A";
  return `${label}) Score ${clone.score}. Primary words: ${mainWords}. `
    + `Start ${startCoord}, ${horizontal ? "horizontal" : "vertical"}. `
    + `Placements: ${placements || "none"}.`;
}

function rackLetters(player) {
  return player.rack.tiles()
  .map(tile => {
    if (tile.isBlank)
      return tile.letter ? tile.letter.toLowerCase() : "_";
    return tile.letter;
  })
  .join("");
}

function sanitizeJson(content) {
  if (!content)
    return null;
  const trimmed = content.trim();
  const match = trimmed.match(/\{[\s\S]*\}/);
  const jsonLike = match ? match[0] : trimmed;
  try {
    return JSON.parse(jsonLike);
  } catch (err) {
    return null;
  }
}

function parseChoice(content) {
  const parsed = sanitizeJson(content);
  if (parsed && parsed.choice)
    return {
      choice: String(parsed.choice).trim().toUpperCase(),
      reason: parsed.reason || ""
    };
  // Fallback: look for capital letter option
  const match = content && content.match(/[A-Z]/);
  return {
    choice: match ? match[0] : "A",
    reason: content || ""
  };
}

export async function chooseYobotPlay(game, player, candidates, config = {}) {
  if (!candidates || !candidates.length)
    return null;
  const apiKey = config.openai_key;
  if (!apiKey)
    return candidates[0];
  const fetchImpl = (typeof fetch === "function") ? fetch : null;
  if (!fetchImpl)
    throw new Error("fetch is not available for Yobot strategy");
  const model = config.yobot_model || "gpt-4o-mini";
  const endpoint = config.yobot_base_url || DEFAULT_ENDPOINT;
  const temperature = typeof config.temperature === "number"
    ? config.temperature : 0.2;

  const debugEnabled = !!(config && config.debugYobot);
  const tracer = debugEnabled
        ? (typeof game._debug === "function" ? game._debug : console.log)
        : null;
  const boardText = boardToAscii(game.board);
  const rack = rackLetters(player);
  if (tracer) {
    tracer("Yobot candidates:");
    candidates.forEach((move, idx) => {
      const summary = summarizeCandidate(move, idx, game.board);
      tracer(`  ${summary}`);
    });
  }

  const bagRemaining = (game.letterBag
    && typeof game.letterBag.remainingTileCount === "function")
    ? game.letterBag.remainingTileCount() : undefined;
  const threats = describePremiumThreats(game.board);
  const options = candidates
  .map((move, idx) => summarizeCandidate(move, idx, game.board))
  .join("\n");

  const systemPrompt =
        "You are Yobot, an expert Scrabble strategist. "
        + "Choose the safest strong move that balances scoring with board control. "
        + "Prefer plays that limit opponent access to premium squares when scores are similar. "
        + "Respond in compact JSON: {\"choice\":\"A\",\"reason\":\"short explanation\"}.";

  const userPrompt = [
    `Board:\n${boardText}`,
    `Player rack: ${rack}`,
    typeof bagRemaining === "number"
      ? `Tiles left in bag: ${bagRemaining}` : null,
    `Premium squares to protect: ${threats}`,
    "Candidate moves:",
    options
  ].filter(Boolean).join("\n\n");

  let content;
  try {
    const response = await fetchImpl(endpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${apiKey}`
      },
      body: JSON.stringify({
        model,
        temperature,
        max_tokens: 400,
        messages: [
          { role: "system", content: systemPrompt },
          { role: "user", content: userPrompt }
        ]
      })
    });
    if (!response.ok) {
      const text = await response.text();
      throw new Error(`Yobot HTTP ${response.status}: ${text}`);
    }
    const payload = await response.json();
    content = payload.choices
      && payload.choices[0]
      && payload.choices[0].message
      && payload.choices[0].message.content;
  } catch (err) {
    console.error("Yobot API error:", err.message || err);
    return candidates[0];
  }

  const parsed = parseChoice(content || "");
  const choiceLetter = parsed.choice || "A";
  const charCode = choiceLetter.charCodeAt(0);
  const normalizedIndex = Number.isFinite(charCode) ? charCode - 65 : 0;
  const index = Math.max(
    0, Math.min(candidates.length - 1, normalizedIndex));
  const selection = candidates[index] || candidates[0];
  if (selection) {
    selection._yobotLabel = choiceLetter;
    selection._yobotReason = parsed.reason || "";
    if (tracer)
      tracer(`Yobot chose ${choiceLetter}: ${selection.stringify()} (${selection.score}) => ${selection._yobotReason || "No reason provided"}`);
  }
  return selection;
}
