import type { TestDef } from "../testKit.js";
import { discoveryTests } from "./discovery.js";
import { authTests } from "./auth.js";
import { authzTests } from "./authz.js";
import { fieldAuthzTests } from "./fieldauthz.js";
import { inputTests } from "./input.js";
import { mutationTests } from "./mutation.js";
import { dosTests } from "./dos.js";
import { exposureTests } from "./exposure.js";
import { configTests } from "./config.js";
import { corsCsrfTests } from "./corscsrf.js";
import { ssrfTests, subscriptionTests, logicTests, uploadTests, extApiTests, loggingTests } from "./guided.js";

export const ALL_TEST_DEFS: TestDef[] = [
  ...discoveryTests,
  ...authTests,
  ...authzTests,
  ...fieldAuthzTests,
  ...inputTests,
  ...mutationTests,
  ...dosTests,
  ...exposureTests,
  ...subscriptionTests,
  ...logicTests,
  ...uploadTests,
  ...ssrfTests,
  ...configTests,
  ...corsCsrfTests,
  ...extApiTests,
  ...loggingTests,
];

export const TEST_DEF_BY_ID: Map<string, TestDef> = new Map(ALL_TEST_DEFS.map((t) => [t.id, t]));
