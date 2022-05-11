package com.mostafaeldahshan.securityapi.security;

import com.google.common.collect.Sets;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Set;
import java.util.stream.Collectors;

import static com.mostafaeldahshan.securityapi.security.ApplicationUserPermission.*;

public enum ApplicationUserRole {
    STUDENT(Sets.newHashSet()), // giving student no permissions
    ADMIN(Sets.newHashSet(COURSE_READ, COURSE_WRITE, STUDENT_READ, STUDENT_WRITE)), //giving admin read/write permissions
    ADMINTRAINEE(Sets.newHashSet(COURSE_READ, STUDENT_READ)); // giving admintrainee read only permissions

    private final Set<ApplicationUserPermission> permissions;

    ApplicationUserRole(Set<ApplicationUserPermission> permissions) {
        this.permissions = permissions;
    }

    public Set<ApplicationUserPermission> getPermissions() {
        return permissions;
    }

    public Set<SimpleGrantedAuthority> getGrantedAuthorities()// returning authorities of specific role.
    {
        Set<SimpleGrantedAuthority> permissions = getPermissions().stream()
                // mapping new permission to SimpleGrantAuthority object
                .map(permission -> new SimpleGrantedAuthority(permission.getPermission()))
                .collect(Collectors.toSet());
        permissions.add(new SimpleGrantedAuthority("ROLE_" + this.name()));
        return permissions;
    }
}
