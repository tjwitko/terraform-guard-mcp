import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, rmSync } from "fs";
import { tmpdir } from "os";
import path from "path";
import { censusOf, findRemovedResources } from "../lib/resource-census.mjs";

function tempDir() {
  return mkdtempSync(path.join(tmpdir(), "tfguard-census-"));
}

test("censusOf finds resource and module declarations", () => {
  const dir = tempDir();
  try {
    writeFileSync(
      path.join(dir, "main.tf"),
      `resource "aws_s3_bucket" "logs" {}\nmodule "vpc" { source = "./vpc" }\n`
    );
    const c = censusOf(dir);
    assert.ok(c.has("aws_s3_bucket.logs"));
    assert.ok(c.has("module.vpc"));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// The exact failure this module exists for: a model rewrote main.tf while fixing an unrelated
// validation error and silently dropped the S3 bucket the whole project was about.
test("findRemovedResources reports resources dropped by a rewrite", () => {
  const dir = tempDir();
  try {
    writeFileSync(
      path.join(dir, "main.tf"),
      `resource "aws_s3_bucket" "logs" {}\nresource "aws_s3_bucket_object_lock_configuration" "lock" {}\n`
    );
    assert.deepEqual(findRemovedResources(dir), [], "first scan has no prior record to compare");

    writeFileSync(path.join(dir, "main.tf"), `resource "aws_vpc" "main" {}\n`);
    const removed = findRemovedResources(dir).sort();
    assert.deepEqual(removed, ["aws_s3_bucket.logs", "aws_s3_bucket_object_lock_configuration.lock"]);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("findRemovedResources stays quiet when resources are only added", () => {
  const dir = tempDir();
  try {
    writeFileSync(path.join(dir, "main.tf"), `resource "aws_s3_bucket" "logs" {}\n`);
    findRemovedResources(dir);
    writeFileSync(
      path.join(dir, "main.tf"),
      `resource "aws_s3_bucket" "logs" {}\nresource "aws_vpc" "main" {}\n`
    );
    assert.deepEqual(findRemovedResources(dir), []);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("commented-out resources do not count as present", () => {
  const dir = tempDir();
  try {
    writeFileSync(path.join(dir, "main.tf"), `resource "aws_s3_bucket" "logs" {}\n`);
    findRemovedResources(dir);
    writeFileSync(path.join(dir, "main.tf"), `# resource "aws_s3_bucket" "logs" {}\n`);
    assert.deepEqual(findRemovedResources(dir), ["aws_s3_bucket.logs"]);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
