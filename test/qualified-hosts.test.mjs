// 已验证宿主清单不能只靠手上的机器"跑通了"：每条都要留宿主源码级的回归证据。
// test/fixtures/verified-hosts.json 是证据，本文件负责把证据和 lib/community.js 对齐。
import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { QUALIFIED_HOST_VERSIONS } from "../lib/community.js";

const fixture = JSON.parse(
  fs.readFileSync(new URL("./fixtures/verified-hosts.json", import.meta.url), "utf8"),
);

test("有回归证据的宿主必须已进 QUALIFIED_HOST_VERSIONS", () => {
  assert.ok(Array.isArray(fixture.hosts) && fixture.hosts.length > 0);
  for (const host of fixture.hosts) {
    assert.ok(
      QUALIFIED_HOST_VERSIONS.includes(host.version),
      `${host.version} 有回归证据，却没有进 QUALIFIED_HOST_VERSIONS`,
    );
  }
});

test("进清单的宿主必须零漂移，例外逐条可解释", () => {
  for (const host of fixture.hosts) {
    assert.equal(typeof host.checked, "number", `${host.version} 缺少 checked`);
    assert.equal(host.drifted, 0, `${host.version} 存在补丁锚点漂移，不能标为已验证`);
    for (const id of host.optional_drift || []) {
      assert.equal(typeof id, "number");
      assert.ok(host.explain?.[String(id)], `${host.version} 的 optional #${id} 没有解释`);
    }
    for (const id of host.chained || []) {
      assert.equal(typeof id, "number");
      assert.ok(host.explain?.[String(id)], `${host.version} 的 chained #${id} 没有解释`);
    }
    for (const id of host.target_file_missing || []) {
      assert.equal(typeof id, "number");
      assert.ok(host.explain?.[String(id)], `${host.version} 的缺目标 #${id} 没有解释`);
    }
    assert.ok(host.source, `${host.version} 缺少证据来源`);
    assert.match(host.measured_at, /^\d{4}-\d{2}-\d{2}$/, `${host.version} 缺少核实日期`);
  }
});

test("清单里只有 0.2.1 预发布宿主，且不重复", () => {
  assert.equal(new Set(QUALIFIED_HOST_VERSIONS).size, QUALIFIED_HOST_VERSIONS.length);
  for (const version of QUALIFIED_HOST_VERSIONS) {
    assert.match(version, /^0\.2\.1-rc\.\d+$/, `${version} 不是已验证过的宿主形态`);
  }
  // 清单是不断追加的：rc.3 及更早的结论不能被后来的版本冲掉。
  for (const keep of ["0.2.1-rc.1", "0.2.1-rc.2", "0.2.1-rc.3", "0.2.1-rc.5"]) {
    assert.ok(QUALIFIED_HOST_VERSIONS.includes(keep), `${keep} 不该从清单里消失`);
  }
});
