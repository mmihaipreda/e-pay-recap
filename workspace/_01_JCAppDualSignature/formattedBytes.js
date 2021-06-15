const input =
    "6b, 43, 04, 8d, 0d, 81, 9e, a3, 40, 1e, 2a, cf, c1, 95, e0, da, 47, 6f, e9, 42, 0e, da, 5b, 97, ae, 06, 43, 96, 63, a9, 85, 76, 5e, f1, df, bf, a9, d3, 4d, 8f, 37, 45, fe, 7a, 9c, 08, a1, 5d, f8, d8, 8f, cc, 3a, 7d, 06, e0, f9, 4a, 19, 9d, ca, b1, 95, 83, e2, ff, aa, 5b, 14, fa, 63, a1, 4c, 5f, 37, 92, 2e, bb, d6, f1, 7b, 8a, dd, a7, d8, 1e, 3e, 11, a2, 8f, 7f, 13, 93, b2, 9a, 3d, 8a, de, ae, ad, a0, f2, 93, 98, e9, 98, 33, 61, 2f, 68, c3, 74, c2, 59, 21, bd, 68, cd, d9, 53, fd, 58, 5a, 01, 42, a7, 3c, 25, ef, 07, 78, ab, 10, 05, 11, 8c, 90, b8, d4, 39, 7f, 3b, 92, d5, 85, b5, f3, 2e, 4b, 07, f3, d8, 95, 6e, 4b, 6a, 74, 74, 64, 0d, ec, 4f, 7c, c9, 15, 41, 23, d3, fc, 36, 37, 5d, ee, 9d, 21, 1f, d4, 6d, bb, 10, bd, 9b, 39, 79, e0, 5c, 7a, cc, 19, 9f, 22, f6, 94, 6e, 9c, 04, 6b, 93, 6d, 9d, 17, c4, b0, f6, 4b, 1d, a8, 0a, 26, 10, 92, f9, 6b, 7d, 12, 07, 03, b5, 64, 73, 06, d3, 9d, 06, 40, d8, c9, 79, d5, 3d, 42, 8b, c7, 29, d4, 9b, 38, 67, ad, 76, f2, e8, 18, 90, 60, 24, b4, 1a, 11, 82, 38, af, 4d, b7, ce, 76";

const formattedInput = input.split(",");
for (let i = 0; i < formattedInput.length; ++i) {
    formattedInput[i] = `0x${formattedInput[i].trim()}`;
}

console.log(formattedInput.join(" "));