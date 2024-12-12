package main.springjwt.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
@ResponseBody
public class AuthController {

    @GetMapping("/admin")
    public String adminP() {
        return "auth Controller";
    }
}
