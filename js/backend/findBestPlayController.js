/*Copyright (C) 2019-2022 The Xanado Project https://github.com/cdot/Xanado
  License MIT. See README.md at the root of this distribution for full copyright
  and license information. Author Crawford Currie http://c-dot.co.uk*/
/**
 * This is the controller side of a best play thread. It provides
 * the same API as findBestPlay(). See also findBestPlayWorker.js
 */
define([
  "worker_threads",
  "platform",
  "common/Fridge",
  "backend/BackendGame"
], (
  threads,
  Platform,
  Fridge,
  Game
) => {

  /**
   * Interface is the same as for {@linkcode findBestPlay} so they
   * can be switched in and out.
   */
  function findBestPlayController(
    game, letters, listener, dictionary) {
    const ice = {
      workerData: Fridge.freeze({
        game: game,
        rack: letters,
        dictionary: dictionary
      })
    };
    return new Promise((resolve, reject) => {
      const worker = new threads.Worker(
        Platform.getFilePath("js/backend/findBestPlayWorker.js"), ice);

      // Apply the game time limit
      let timer;
      if (game.timerType === Game.Timer.TURN) {
        /* istanbul ignore next */
        timer = setTimeout(() => {
          console.error("findBestPlay timed out");
          worker.terminate();
        }, game.timeAllowed * 60000);
      }

      // Pass worker messages on to listener
      worker.on("message", data => {
        listener(Fridge.thaw(data, Game));
      });

      /* istanbul ignore next */
      worker.on("error", e => {
        if (timer)
          clearTimeout(timer);
        reject(e);
      });

      worker.on("exit", (code) => {
        if (timer)
          /* istanbul ignore next */
          clearTimeout(timer);
        /* istanbul ignore if */
        if (code !== 0)
          console.error(`findBestPlayWorker reported code ${code}`);
        resolve();
      });
    });
  }

  return findBestPlayController;
});
