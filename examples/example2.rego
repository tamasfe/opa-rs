package example2

project_permissions2[action] {
    user_project2.roles[_] == "owner"
    action = "read"
}

project_permissions2[action] {
    user_project2.roles[_] == "owner"
    action = "write"
}

user_project2 = project {
	project = data.users[input.user_id].projects[input.project_id]
}
