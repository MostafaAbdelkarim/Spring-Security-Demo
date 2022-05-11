package com.mostafaeldahshan.securityapi.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/")
public class TemplateController { // using thymeleaf to navigate throught pages using HTTP requests

    @GetMapping("login")
    public String getLogin()
    {
        return "login";
    }
    @GetMapping("courses")
    public String getCourses()
    {
        return "courses";
    }
}
