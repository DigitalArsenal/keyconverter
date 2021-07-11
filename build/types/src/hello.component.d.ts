import { HelloService } from "./hello-service.interface";
export declare class HelloComponent {
    private helloService;
    constructor(helloService: HelloService);
    sayHello(): string;
}
