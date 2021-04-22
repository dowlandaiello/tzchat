var exports = {"__esModule": true};

import { createIcon } from "./blockies.mjs";

// The domain the page is being served on
let [_, isHttps, domain] = document.location.toString().match(/http(s?):\/\/(.+)\//);
let wsPath = `${!isHttps ? "ws" : "wss"}://${domain}/ws/`;
let currentRoom = "";

// Websockets should be served from the root of the webpage + /ws/
const sock = new WebSocket(wsPath);

// Handle incoming messages
const messageHolder = document.getElementById("messagesHolder");
const messageTemplate = document.getElementById("message");

sock.addEventListener("message", (e) => {
	const rawMessage = e.data;
	const [, , sender, msg] = rawMessage.split("␝");

	// Customize a message UI element to contain the message details
	let messageNode = messageTemplate.content.cloneNode(true);

	// Generate a blocky profile picture for the user
	let pfp = createIcon({seed: "tzchat"});
	pfp.setAttribute("class", "pfp");
	messageNode.querySelector(".pfp").replaceWith(pfp);

	messageNode.querySelector(".author").innerHTML = sender;
	messageNode.querySelector(".msg-text").innerHTML = msg;

	messageHolder.appendChild(messageNode);
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

window.sendMessage = e => {
	e.preventDefault();

	// Send the message
	sock.send(`MSG␝${currentRoom}␝${currentAlias}␝${msgInput.value}`);
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
chooseAliasButton.addEventListener("touchend", showAliasModal);
chooseAliasButton.addEventListener("click", showAliasModal);

const showAliasModal = e => {
	e.preventDefault();

	// Request the user's aliases from the server
}
