document.getElementById("newIdentity").onclick = function() {
        browser.runtime.sendMessage({
              data: "msg"
        })
}