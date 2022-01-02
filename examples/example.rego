package example

project_permissions[action] {
    user_project.roles[_] == "owner"
    action = "read"
}

project_permissions[action] {
    user_project.roles[_] == "owner"
    action = "write"
}

user_project = project {
	project = data.users[input.user_id].projects[input.project_id]
}
