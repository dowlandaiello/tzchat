var exports = {"__esModule": true};

import { createIcon } from "./blockies.mjs";

// The domain the page is being served on
let [_, isHttps, domain] = document.location.toString().match(/http(s?):\/\/(.+)\//);
let wsPath = `${!isHttps ? "ws" : "wss"}://${domain}/ws/`;
let currentRoom = "";
let currentAlias = "";

// Websockets should be served from the root of the webpage + /ws/
const sock = new WebSocket(wsPath);

// Handle incoming messages
const messageHolder = document.getElementById("messagesHolder");
const messageTemplate = document.getElementById("message");

sock.addEventListener("message", (e) => {
	if (e.data.includes("error")) {
		console.error(e);

		return;
	}

	// TODO: Create a message queue that 
	const rawMessage = e.data;
	let [, , sender, msg] = rawMessage.split("␝");

	// Get all lines like:
	// > Green text
	msg = msg.replaceAll(/^(> {0,1}.+)(?=$|\n)/gm, '<span class="greentext">$1</span>');
	msg = msg.replaceAll("\n", "<br>");

	// Customize a message UI element to contain the message details
	let messageNode = messageTemplate.content.cloneNode(true);

	// Generate a blocky profile picture for the user
	let pfp = createIcon({seed: sender});
	pfp.setAttribute("class", "pfp");
	messageNode.querySelector(".pfp").replaceWith(pfp);

	messageNode.querySelector(".author").innerHTML = sender;
	messageNode.querySelector(".msg-text").innerHTML = msg;

	messageHolder.appendChild(messageNode);
	messageHolder.scrollTop = messageHolder.scrollHeight;
});

// The user wishes to join a room
const roomLabel = document.getElementById("roomNameLabel");
const roomNameInput = document.getElementById("roomName");

const joinRoom = roomName => {
	// Join the specified room
	currentRoom = roomName;
	sock.send(`JOIN_ROOM␝${currentRoom}`);

	roomLabel.innerHTML = `#${currentRoom}`;

	// Show the user the new room
	document.title = `#${currentRoom}: tzhs.chat`
	messageHolder.value = "";

};

window.handleJoinEvent = e => {
	e.preventDefault();

	joinRoom(roomNameInput.value);
};

// The user wants to send a message in the current room
const msgInput = document.getElementById("msgCts");
const sendMsgButton = document.getElementById("sendMsg");

msgInput.addEventListener("keypress", (e) => {
	if (e.key != "Enter") {
		return;
	}

	if (e.shiftKey) {
		return;
	}

	sendMessage(e);
})

window.sendMessage = e => {
	e.preventDefault();

	if (!currentAlias) {
		alert("Before sending a message, please select a username by clicking the user settings icon.");

		return;
	}

	// Send the message
	sock.send(`MSG␝${currentRoom}␝${currentAlias}␝${msgInput.value}`);

	msgInput.value = ""; 
};

sendMsgButton.addEventListener("touchend", window.sendMessage);
sendMsgButton.addEventListener("click", window.sendMessage);


// The user wants to register a username
window.addUsername = e => {
	e.preventDefault();

	// Register the username
	const username = document.getElementById("username").value;
	sock.send(`USE_ALIAS␝${username}`);
};

// Once the user has joined the chat, join general
sock.addEventListener("open", (e) => {
	console.log("successfully connected to chat server");

	// Join general by default
	joinRoom("general");
});

// Handle alias registration
const chooseAliasButton = document.getElementById("chooseAcc");

// Make a modal to show to the user
let aliasModal = document.querySelector("#modal").content.cloneNode(true);
aliasModal.getElementById("title").innerHTML = "Profiles";
document.body.appendChild(aliasModal);
document.getElementById("some-id").setAttribute("id", "aliasModal")

aliasModal = document.querySelector("#aliasModal");

let newAliasButton = aliasModal.querySelector(".choices").children[0];

// Allow users to choose from the aliases that they have
const chooseNewAlias = e => {
	e.preventDefault();

	currentAlias = e.target.innerHTML;
	msgInput.setAttribute("placeholder", `Send a message as ${currentAlias}`)

	reloadModal();
};

let choiceTemplate = newAliasButton.cloneNode(true);

newAliasButton.innerHTML = "Claim New Username +";
newAliasButton.setAttribute("style", "font-weight: bold;");

// Refetches the list of aliases in the alias modal
const reloadModal = () => fetch(
		"/api/aliases", {credentials: "same-origin"}
	).then(resp => resp.json()).then(aliases => {
		let choiceContainer = aliasModal.querySelector(".choices");

		// Remove all choices EXCEPT the new username button
		Array.from(choiceContainer.children).filter((node) => node != newAliasButton).forEach((node) => node.remove());

		aliases.forEach((alias) => {
			// Allow the user to choose the alias
			let choiceButton = choiceTemplate.cloneNode(true);
			choiceButton.addEventListener("touchend", chooseNewAlias);
			choiceButton.addEventListener("click", chooseNewAlias)
			choiceButton.innerHTML = alias;

			if (alias === currentAlias) {
				choiceButton.setAttribute("style", "font-weight: bold");
			}

			choiceContainer.insertBefore(choiceButton, newAliasButton);
		})
	});

const showAliasModal = e => {
	e.preventDefault();

	reloadModal()
		.then(() => aliasModal.setAttribute("visible", true));
};

chooseAliasButton.addEventListener("touchend", showAliasModal);
chooseAliasButton.addEventListener("click", showAliasModal);

// Let the user exit a modal
const closeModal = e => {
	e.preventDefault();

	let enclosingModal = e.target.parentNode.parentNode.parentNode;
	enclosingModal.removeAttribute("visible");
};

let closeModalButtons = document.querySelectorAll(".close-button");
closeModalButtons.forEach((closeBtn) => {
	closeBtn.addEventListener("touchend", closeModal);
	closeBtn.addEventListener("click", closeModal);
});

// Handle clicks on the new username button
const claimAlias = e => {
	e.preventDefault();

	const alias = prompt("Enter the username you would like to claim");
	if (!alias) {
		return;
	}

	// Claim the alias
	sock.send(`USE_ALIAS␝${alias}`);
	reloadModal();
}

newAliasButton.addEventListener("touchend", claimAlias);
newAliasButton.addEventListener("click", claimAlias);
