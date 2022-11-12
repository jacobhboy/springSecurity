package spring.security.springsecuritybasic;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SecurityController {

    @GetMapping("/")
    public String index(){
        return "home";
    }

    @GetMapping("/loginPage")
    public String LoginPage(){
        return "loginPage";
    }

    @GetMapping("/aa")
    public String aa(){
        return "aa";
    }
}
