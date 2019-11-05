document.getElementById("newIdentity").onclick = function() {
        alert("Are you sure? If you need to back out, exit this tab."); browser.runtime.sendMessage({
              data: "msg"
        });
}
