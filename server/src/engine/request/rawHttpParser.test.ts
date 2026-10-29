import { describe, it, expect } from "vitest";
import { parseRawHttp } from "./rawHttpParser.js";
import { toGET, toFormEncoded, withOperation, getHeader } from "./requestModel.js";

const SAMPLE = `POST http://10.164.3.88:32907/graphql HTTP/1.1
Host: 10.164.3.88:32907
Content-Length: 440
authorization:
Accept-Language: en-GB,en;q=0.9
accept: */*
content-type: application/json
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36
Origin: https://test.co.ke
Accept-Encoding: gzip, deflate, br
Connection: keep-alive

{"operationName":"RequestWhitelistOtp","variables":{"input":{"phoneNumber":"0724657464"}},"query":"mutation RequestWhitelistOtp($input: RequestWhitelistOtpInput!) {\\n  requestWhitelistOtp(input: $input) {\\n    header {\\n      requestRefId\\n      __typename\\n    }\\n    __typename\\n  }\\n}"}`;

describe("parseRawHttp", () => {
  it("parses the sample RequestWhitelistOtp request", () => {
    const r = parseRawHttp(SAMPLE);
    expect(r.ok).toBe(true);
    const req = r.request!;
    expect(req.method).toBe("POST");
    expect(req.url).toBe("http://10.164.3.88:32907/graphql");
    expect(req.operationName).toBe("RequestWhitelistOtp");
    expect(req.variables).toEqual({ input: { phoneNumber: "0724657464" } });
    expect(req.query).toContain("mutation RequestWhitelistOtp");
    expect(req.headers["content-type"]).toBe("application/json");
    expect(req.headers["Origin"]).toBe("https://test.co.ke");
  });

  it("builds an absolute URL from a relative path + Host header", () => {
    const raw = `POST /graphql HTTP/1.1\nHost: example.com\ncontent-type: application/json\n\n{"query":"{ __typename }"}`;
    const r = parseRawHttp(raw);
    expect(r.ok).toBe(true);
    expect(r.request!.url).toBe("http://example.com/graphql");
  });

  it("fails cleanly on a request with no query", () => {
    const raw = `POST /graphql HTTP/1.1\nHost: example.com\n\n{"foo":"bar"}`;
    const r = parseRawHttp(raw);
    expect(r.ok).toBe(false);
  });
});

describe("requestModel variants", () => {
  const base = parseRawHttp(SAMPLE).request!;

  it("toGET moves the operation into the querystring and drops content-type", () => {
    const g = toGET(base);
    expect(g.method).toBe("GET");
    expect(getHeader(g, "content-type")).toBeUndefined();
  });

  it("toFormEncoded switches the content type", () => {
    const f = toFormEncoded(base);
    expect(getHeader(f, "content-type")).toBe("application/x-www-form-urlencoded");
  });

  it("withOperation keeps auth headers while swapping the operation", () => {
    const probe = withOperation(base, "{ __typename }", undefined, undefined);
    expect(probe.query).toBe("{ __typename }");
    // Original Origin header preserved.
    expect(getHeader(probe, "origin")).toBe("https://test.co.ke");
  });
});
