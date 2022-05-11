package com.mostafaeldahshan.securityapi.student;


public class Student {
    private final Long Id;
    private final String name;

    public Student(Long id, String name) {
        Id = id;
        this.name = name;
    }

    public Long getId() {
        return Id;
    }

    public String getName() {
        return name;
    }

    @Override
    public String toString() {
        return "Student{" +
                "Id=" + Id +
                ", name='" + name + '\'' +
                '}';
    }
}
