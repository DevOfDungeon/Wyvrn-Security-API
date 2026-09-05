const form = document.getElementById("loginForm");

form.addEventListener("submit", (e) => {

    e.preventDefault();

    const role =
        document.getElementById("role").value;

    localStorage.setItem(
        "wyvrnRole",
        role
    );

    window.location.href =
        "dashboard.html";

});