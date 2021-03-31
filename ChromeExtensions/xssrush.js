let doXSS = document.getElementById("doXSS");
let body = document.getElementById("body");
let footer = document.getElementById("footer");


footer.onclick = function(){
	chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
		chrome.tabs.executeScript(tabs[0].id,{code:`window.open("https://xssr.n45ht.or.id");`});});
};

doXSS.onclick = function(element) {
	chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
		chrome.tabs.executeScript(
			tabs[0].id,
		  {code:`div=document.createElement("div"),div.removeAttribute("style"),div.setAttribute("style","background-color:#1a2035;color:#ffffff;width:200px;height:50px;bottom:15px;right:15px;z-index:16777271;border-radius:0.2rem;text-align:center;font-family:'Roboto', 'Helvetica', 'Arial', sans-serif;position:fixed;box-shadow: 0 5px 4px 0 rgba(0,0,0,.26);border: 1px solid rgba(255,255,255,0.2);"),div.innerHTML="<h4 style='margin-top:12px;font-size: 1.125rem;line-height: 1.4em;font-weight: 300;'>Running XSSR!</h4>",document.body.appendChild(div),setTimeout(function(){div.remove()},1e3);var xhttp=new XMLHttpRequest;xhttp.onreadystatechange=function(){4==this.readyState&&200==this.status?(resJson=JSON.parse(this.responseText),1==resJson.status?(div=document.createElement("div"),div.removeAttribute("style"),div.setAttribute("style","background-color:#1a2035;color:#ffffff;width:200px;height:50px;bottom:15px;right:15px;z-index:16777271;border-radius:0.2rem;text-align:center;font-family:'Roboto', 'Helvetica', 'Arial', sans-serif;position:fixed;box-shadow: 0 5px 4px 0 rgba(0,0,0,.26);"),div.innerHTML="<h4 style='margin-top:12px;font-size: 1.125rem;line-height: 1.4em;font-weight: 300;'>"+resJson.message+"</h4>",document.body.appendChild(div),setTimeout(function(){div.remove()},2e3),window.open(resJson.poc,"","width=420,height=280,top=360,left=890")):(div=document.createElement("div"),div.removeAttribute("style"),div.setAttribute("style","background-color:#1a2035;color:#ffffff;width:200px;height:50px;bottom:15px;right:15px;z-index:16777271;border-radius:0.2rem;text-align:center;font-family:'Roboto', 'Helvetica', 'Arial', sans-serif;position:fixed;box-shadow: 0 5px 4px 0 rgba(0,0,0,.26);"),div.innerHTML="<h4 style='margin-top:12px;font-size: 1.125rem;line-height: 1.4em;font-weight: 300;'>"+resJson.message+"</h4>",document.body.appendChild(div),setTimeout(function(){div.remove()},2e3))):403==this.status&&(div=document.createElement("div"),div.removeAttribute("style"),div.setAttribute("style","background-color:#1a2035;color:#ffffff;width:200px;height:50px;bottom:15px;right:15px;z-index:16777271;border-radius:0.2rem;text-align:center;font-family:'Roboto', 'Helvetica', 'Arial', sans-serif;position:fixed;box-shadow: 0 5px 4px 0 rgba(0,0,0,.26);"),div.innerHTML="<h4 style='margin-top:12px;font-size: 1.125rem;line-height: 1.4em;font-weight: 300;'>Failed!</h4>",document.body.appendChild(div),setTimeout(function(){div.remove()},2e3))},xhttp.open("GET","https://xssr.n45ht.or.id/api/doXSSRChrome?url="+encodeURIComponent(window.location.href.replace(window.location.hash,"")),!0),xhttp.send();`});
	});
};
