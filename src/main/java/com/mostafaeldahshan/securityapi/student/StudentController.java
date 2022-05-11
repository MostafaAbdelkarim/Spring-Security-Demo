package com.mostafaeldahshan.securityapi.student;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@RestController // defining as rest controller
@RequestMapping("/api/v1/students") // specifying the uri for rest api access
public class StudentController {

    private static final List<Student> students = Arrays.asList( //statically creating list of students for testing
        new Student(1L,"Ahmed"),
        new Student(2L,"Youssry"),
        new Student(3L,"Medhat")
    );

    @GetMapping("{studentId}") // defining this function as GET method to be called when using API giving it /{id}
    public Student getStudent(@PathVariable("studentId") Long Id) // Linking function arguments to GET using @PathVariable
    {
        // using stream framework to manipulate the list of students
        return students.stream()
                .filter(student -> Id.equals(student.getId()))
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("Student not found"));
    }
}
