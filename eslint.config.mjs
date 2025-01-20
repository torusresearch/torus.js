import toruslabsTypescript from "@toruslabs/eslint-config-typescript";

export default [
  ...toruslabsTypescript,
  {
    rules: {
      "no-unused-vars": "off",
      "no-implicit-any": "off",
    },
  },
];
