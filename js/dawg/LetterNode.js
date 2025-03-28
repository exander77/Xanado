/*Copyright (C) 2019-2022 The Xanado Project https://github.com/cdot/Xanado
  License MIT. See README.md at the root of this distribution for full copyright
  and license information. Author Crawford Currie http://c-dot.co.uk*/
/* eslint-env amd, node */

define([
  "platform"
], (
  Platform
) => {

  /**
   * Letter node in a Dictionary. Each node has multiple links and helpers
   * that trade off space for performance during word searches.
   * Each LetterNode participates in two linked lists; the `next` pointer
   * points to the next alternative to this letter when composing a word,
   * while the `child` pointer points to the first in a chain of possible
   * child nodes. For example, in a dictionary where we have the two words
   * `NO`, `SO` and `SAD`:
   * ```
   *   N -next-> S -next->
   *   |         |
   * child     child
   *   |         |
   *   `-> O(e)  `-> A -next-> O(e)
   *                 |
   *               child
   *                 |
   *                 D(e)
   * ```
   * where (e) indicates a node that is a valid end-of-word.
   * The example is a tree; however the DAWG compressor will
   * collapse letter sequences that are common to several words,
   * to create a more optimal DAG.
   *
   * Once a Dictionary has been created and fully populated, it can be
   * processed using `buildLists` to generate lists that support rapid
   * navigation through the DAG without needing to traverse the node
   * chains.
   */
  class LetterNode {

    /**
     * Bit mask for end-of-word marker
     * @member {number}
     */
    static END_OF_WORD_BIT_MASK = 0x1;

    /**
     * Bit mask for end-of-list marker
     * @member {number}
     */
    static END_OF_LIST_BIT_MASK = 0x2;

    /**
     * Shift to create space for masks
     * @member {number}
     */
    static CHILD_INDEX_SHIFT = 2;

    /**
     * Mask for child index, exclusing above bit masks
     * @member {number}
     */
    static CHILD_INDEX_BIT_MASK = 0x3FFFFFFF;

    /**
     * Pointer to the next (alternative) node in this peer chain.
     * During loading this will be a number that will be converted
     * to a pointer.
     * @member {(number|LetterNode)?}
     */
    next;

    /**
     * Pointer to the head of the child chain
     * @member {LetterNode?}
     */
    child;

    /**
     * Is this the end of a valid word?
     * @member {boolean}
     */
    isEndOfWord = false;

    /**
     * List of nodes that link forward to this node. Set up
     * by {@linkcode LetterNode#buildLists|buildLists}.
     * @member {LetterNode[]?}
     */
    preNodes;

    /**
     * List of letters that are in the nodes listed in `preNodes`.
     * Set up by {@linkcode LetterNode#buildLists|buildLiss}.
     * @member {string[]?}
     */
    preLetters;

    /**
     * List of nodes that are linked to from this node. Set up
     * by {@linkcode LetterNode#buildLists|buildLists}.
     * @member {LetterNode[]?}
     */
    postNodes;

    /**
     * List of letters that are in the nodes listed in `postNode`.
     * Set up by {@linkcode LetterNode#buildLists|buildLists}.
     * @member {LetterNode[]?}
     */
    postLetters;

    constructor(letter) {
      /**
       * The letter at this node
       * @member {string}
       */
      this.letter = letter;
    }

    /**
     * @callback LetterNode~wordCallback
     * @param {string} word found
     * @param {LetterNode} node node where word was terminated
     */

    /**
     * Enumerate each word in the dictionary. Calls cb on each word.
     * @param {string} s the word constructed so far
     * @param {LetterNode~wordCallback} cb the callback
     */
    eachWord(s, cb) {
      let node = this;

      while (node) {
        if (node.isEndOfWord)
          cb(s + node.letter, node);

        if (node.child)
          node.child.eachWord(s + node.letter, cb);

        node = node.next;
      }
    }

    /**
     * Enumerate each LONG word in the dictionary. A long word is one
     * that has no child nodes i.e. cannot be extended by adding more
     * letters to create a new word. Calls cb on each word.
     * Caution this is NOT the same as dawg/TrieNode.eachWord.
     * @param {string} s the word constructed so far
     * @param {wordCallback} cb the callback
     */
    eachLongWord(s, cb) {
      let node = this;

      while (node) {
        if (node.child)
          node.child.eachLongWord(s + node.letter, cb);
        else if (node.isEndOfWord)
          cb(s + node.letter, node);

        node = node.next;
      }
    }

    /**
     * @callback LetterNode~nodeCallback
     * @param {LetterNode} node node
     * @return {boolean} true to continue the iteration, false to stop it.
     */

    /**
     * Enumerate each node in the dictionary.
     * Calls cb on each node, stops if cb returns false.
     * @param {LetterNode~nodeCallback} cb the callback
     */
    eachNode(cb) {
      let node = this;

      while (node) {
        if (!cb(node))
          return false;

        if (node.child && !node.child.eachNode(cb))
          return false;

        node = node.next;
      }
      return true;
    }

    /**
     * Add a letter sequence to this node. This is used to add
     * whitelist nodes to a DAG.
     * @param {string} word word being added
     * @return {boolean} true if the word was added, false if it
     * was already there
     */
    add(word) {
      //console.debug("Adding", word);
      let node = this, added = false;

      while (node) {
        if (node.letter === word.charAt(0)) {
          //console.debug("\tMatched", node.letter);
          if (word.length === 1) {
            if (!node.isEndOfWord) {
              added = true;
              node.isEndOfWord = true;
            }
            return added;
          }
          word = word.substring(1);
          if (!node.child || node.child.letter > word.charAt(0)) {
            //console.debug("\tAdding child", word.charAt(0));
            const t = node.child;
            node.child = new LetterNode(word.charAt(0));
            added = true;
            node.child.next = t;
          }
          //console.debug("\t->child", node.child.letter);
          node = node.child;
        } else if (!node.next || node.next.letter > word.charAt(0)) {
          //console.debug("\tInserting", word.charAt(0), "before", node.next ? node.next.letter: "end");
          const t = node.next;
          node.next = new LetterNode(word.charAt(0));
          added = true;
          node.next.next = t;
        } else {
          node = node.next;
          //console.debug("\t->next", node.letter);
        }
      }
      /* istanbul ignore next */
      return assert.fail(`Unreachable '${word}`);
    }

    /**
     * Build forward and backward lists to allow us to navigate
     * in both directions - forward through words, and backwards too.
     * This has to be done from the root of the DAG, and has to be
     * re-done if the DAG is modified..
     */
    buildLists(nodeBefore) {
      let node = this;

      while (node) {
        node.preNodes = [];
        node.preLetters = [];
        node.postNodes = [];
        node.postLetters = [];
        if (nodeBefore) {
          node.preNodes.push(nodeBefore);
          node.preLetters.push(nodeBefore.letter);
          nodeBefore.postNodes.push(node);
          nodeBefore.postLetters.push(node.letter);
        }
        if (node.child)
          node.child.buildLists(node);
        node = node.next;
      }
    }

    /**
     * Return the LetterNode that matches the last character
     * in chars, even if it"s not isEndOfWord
     * @param {string} chars a string of characters that may
     * be the root of a word
     * @param {number} index the start index within partialWord
     * @return {LetterNode} node found, or undefined
     */
    match(chars, index) {
      let node = this;

      while (node) {
        if (node.letter === chars[index]) {
          if (index === chars.length - 1)
            return node;
          if (node.child)
            return node.child.match(chars, index + 1);
        }
        node = node.next;
      }
      return null;
    }

    /**
     * Find words that can be made from a sorted set of letters.
     * @param {string[]} chars the available set of characters
     * @param {string} realWord the string built so far in this recursion
     * @param {string} blankedWord the string built using spaces for blanks
     * if they are used
     * @param {string[]} foundWords list of words found
     */
    findWordsThatUse(chars, realWord, blankedWord, foundWords) {
      let node = this;

      while (node) {
        // is this character available from chars?
        // Only use blank if no other choice
        let i = chars.indexOf(node.letter);
        if (i < 0) // not there, try blank
          i = chars.indexOf(" ");

        if (i >= 0) {
          const match = chars[i];
          //console.debug("Found", match, "in chars");

          // The char is available from chars.
          // Is this then a word?
          if (node.isEndOfWord) {
            //console.debug("Found", realWord + node.letter);
            // A word is found
            foundWords[realWord + node.letter]
            = blankedWord + match;
          }

          if (chars.length > 1) {
            // Cut the matched letter out of chars and recurse
            // over our child node chain
            chars.splice(i, 1);
            let child = node.child;
            while (child) {
              child.findWordsThatUse(
                chars,
                realWord + node.letter,
                blankedWord + match,
                foundWords);
              child = child.next;
            }
            chars.splice(i, 0, match);
          }
        }

        node = node.next;
      }
    }

    /**
     * Decode node information encoded in an integer in a
     * serialised Dictionary.
     * @param {number} i index of node in node list
     * @param {number} numb encoded node
     * @return {LetterNode} this
     */
    decode(i, numb) {
      if ((numb & LetterNode.END_OF_WORD_BIT_MASK) !== 0)
        this.isEndOfWord = true;
      if ((numb & LetterNode.END_OF_LIST_BIT_MASK) === 0)
        this.next = i + 1;
      if (((numb >> LetterNode.CHILD_INDEX_SHIFT)
           & LetterNode.CHILD_INDEX_BIT_MASK) > 0)
        this.child = ((numb >> LetterNode.CHILD_INDEX_SHIFT)
                      & LetterNode.CHILD_INDEX_BIT_MASK);
      return this;
    }
  }

  return LetterNode;
});
