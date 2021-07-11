import { HelloService } from "../src/hello-service.interface";
import { HelloComponent } from "../src/hello.component";
import { pbkdf2Sync, scryptSync } from "crypto";
import * as bip32 from "bip32";
import * as bip39 from "bip39";

class MockHelloService implements HelloService {

    public sayHello(): string {
        return "Hello world!";
    }
}

describe("HelloComponent", () => {

    it("should say 'Hello world!'", () => {

        let mockHelloService = new MockHelloService();
        let helloComponent = new HelloComponent(mockHelloService);

        expect(helloComponent.sayHello()).to.be("Hello world!");
    });
});
