package com.mostafaeldahshan.securityapi.student;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("management/api/v1/students")
public class StudentManagementController {

    private static final List<Student> students = Arrays.asList(
            new Student(1L,"Ahmed"),
            new Student(2L,"Youssry"),
            new Student(3L,"Medhat")
    );

    @GetMapping
    @PreAuthorize("hasAnyRole('ADMIN','ADMINTRAINEE')") // defining role based authorization to access this function
    public List<Student> getAllStudents()
    {
        System.out.println("GetAllStudents Method");
        return students;
    }

    @PostMapping
    @PreAuthorize("hasAuthority('student:write')") // defining permission based authorization to access this function
    public void registerNewStudent(@RequestBody Student student)
    {
        System.out.println("POST student");
        System.out.println(student);
    }

    @DeleteMapping(path = "{studentId}")
    @PreAuthorize("hasAuthority('student:write')") // defining permission based authorization to access this function
    public void deleteStudent(@PathVariable("studentId") Long studentId)
    {
        System.out.println("Delete Student");
        System.out.println(studentId);
    }

    @PutMapping("{studentId}")
    @PreAuthorize("hasAuthority('student:write')") // defining permission based authorization to access this function
    public void updateStudent(@PathVariable("studentId") Long studentId,@RequestBody Student student)
    {
        System.out.println("Update Student");
    }

}
