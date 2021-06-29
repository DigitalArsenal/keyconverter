import * as assert from "assert";
import { keymaster } from "../src/index";

it("creates a keymaster instance", async function () {
    let km = new keymaster(Buffer.from('asdfasdfasdf'));
});