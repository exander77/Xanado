define(() => {

  const LAYOUT = [
    "M___D___",
    "___d___t",
    "__t___D_",
    "_d___d__",
    "D___t__T",
    "___d__d_",
    "__D__d__",
    "_t__T___"
  ];

  const BAG = [
    { letter: "A", score: 1, count: 9 },
    { letter: "B", score: 4, count: 2 },
    { letter: "C", score: 4, count: 2 },
    { letter: "D", score: 2, count: 5 },
    { letter: "E", score: 1, count: 13 },
    { letter: "F", score: 4, count: 2 },
    { letter: "G", score: 3, count: 3 },
    { letter: "H", score: 3, count: 4 },
    { letter: "I", score: 1, count: 8 },
    { letter: "J", score: 10, count: 1 },
    { letter: "K", score: 5, count: 1 },
    { letter: "L", score: 2, count: 4 },
    { letter: "M", score: 4, count: 2 },
    { letter: "N", score: 2, count: 5 },
    { letter: "O", score: 1, count: 8 },
    { letter: "P", score: 4, count: 2 },
    { letter: "Q", score: 10, count: 1 },
    { letter: "R", score: 1, count: 6 },
    { letter: "S", score: 1, count: 5 },
    { letter: "T", score: 1, count: 7 },
    { letter: "U", score: 2, count: 4 },
    { letter: "V", score: 5, count: 2 },
    { letter: "W", score: 4, count: 2 },
    { letter: "X", score: 8, count: 1 },
    { letter: "Y", score: 3, count: 2 },
    { letter: "Z", score: 10, count: 1 },
    { score: 0, count: 2 }
  ];
  
  return {
    layout: LAYOUT,
    bag: BAG,
    swapCount: 7,
    rackCount: 7,
    bonuses: { 7: 35 } 
  };
});
