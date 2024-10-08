import re
import aiohttp
from redbot.core import commands, Config, checks
from discord.ext import tasks
from collections import defaultdict
from base64 import b64encode
import logging
import discord
import asyncio
from aiohttp import web
import secrets
import base64
import hashlib
from urllib.parse import urlparse, parse_qs, quote
import lyricsgenius
from datetime import datetime, timedelta
from redbot.core import app_commands
from redbot.core.bot import Red

# Add this list at the top of your file or in a separate configuration
OFFENSIVE_WORDS = ["fag", "nigger", "retard", "gay"]  # Add your list of offensive words here

class SpotifyAuthView(discord.ui.View):
    def __init__(self, cog, auth_url):
        super().__init__(timeout=300)
        self.cog = cog
        self.auth_url = auth_url
        self.add_item(discord.ui.Button(label="Authenticate", style=discord.ButtonStyle.link, url=self.auth_url))

    @discord.ui.button(label="Enter Code", style=discord.ButtonStyle.green)
    async def code_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        await interaction.response.send_modal(SpotifyAuthModal(self.cog))

class SpotifyAuthModal(discord.ui.Modal, title="Enter Spotify Auth Code"):
    def __init__(self, cog):
        super().__init__()
        self.cog = cog

    auth_code = discord.ui.TextInput(label="Authorization Code", placeholder="Enter the code from the URL...")

    async def on_submit(self, interaction: discord.Interaction):
        await interaction.response.defer()
        success = await self.cog.get_spotify_token(self.auth_code.value)
        if success:
            await interaction.followup.send("Spotify authentication complete!", ephemeral=True)
        else:
            await interaction.followup.send("Failed to authenticate with Spotify. Please try again.", ephemeral=True)

class PlaylistCreator(commands.Cog):
    def __init__(self, bot: Red):
        self.bot = bot
        self.config = Config.get_conf(self, identifier=1234567890)
        default_global = {
            "channel_id": None,
            "user_id": None,
            "spotify_client_id": None,
            "spotify_client_secret": None,
            "spotify_playlist_id": None,
            "spotify_refresh_token": None,
            "added_tracks": [],
            "last_message_id": None,
            "genius_api_key": None,
        }
        self.config.register_global(**default_global)
        self.url_pattern = re.compile(r'https://open\.spotify\.com/track/([a-zA-Z0-9]+)')
        self.url_check.start()
        self.spotify_token = None
        self.spotify_token_expiry = None
        self.token_refresh_task = self.bot.loop.create_task(self.auto_refresh_token())
        self.logger = logging.getLogger("red.PlaylistCreator")
        self.logger.info("PlaylistCreator cog initialized")
        self.auth_code = None
        self.genius = None

    def cog_unload(self):
        self.url_check.cancel()
        if self.token_refresh_task:
            self.token_refresh_task.cancel()

    playlist_group = app_commands.Group(name="playlist", description="Playlist creator commands")

    @playlist_group.command(name="set_channel")
    @app_commands.describe(channel="The channel to monitor for Spotify links")
    async def set_channel(self, interaction: discord.Interaction, channel: discord.TextChannel):
        """Set the channel to monitor for Spotify links."""
        await self.config.channel_id.set(channel.id)
        await interaction.response.send_message(f"Channel set to {channel.mention}")

    @playlist_group.command(name="set_user")
    @app_commands.checks.has_permissions(administrator=True)
    async def set_user(self, interaction: discord.Interaction, user: discord.User):
        """Set the user ID for Spotify authentication."""
        await self.config.user_id.set(user.id)
        await interaction.response.send_message(f"User set to {user.mention}")

    @playlist_group.command(name="set_spotify_credentials")
    @app_commands.checks.has_permissions(administrator=True)
    async def set_spotify_credentials(self, interaction: discord.Interaction, client_id: str, client_secret: str):
        """Set Spotify API credentials."""
        await interaction.response.defer(ephemeral=True)
        await self.config.spotify_client_id.set(client_id)
        await self.config.spotify_client_secret.set(client_secret)
        await interaction.followup.send("Spotify credentials set.", ephemeral=True)

    @playlist_group.command(name="set_spotify_playlist")
    @app_commands.checks.has_permissions(administrator=True)
    async def set_spotify_playlist(self, interaction: discord.Interaction, playlist_id: str):
        """Set Spotify playlist ID."""
        await self.config.spotify_playlist_id.set(playlist_id)
        await interaction.response.send_message(f"Spotify playlist ID set to {playlist_id}")

    @playlist_group.command(name="set_genius_api_key")
    @app_commands.checks.has_permissions(administrator=True)
    async def set_genius_api_key(self, interaction: discord.Interaction, api_key: str):
        """Set the Genius API Key."""
        await interaction.response.defer(ephemeral=True)
        await self.config.genius_api_key.set(api_key)
        self.genius = lyricsgenius.Genius(api_key)
        await interaction.followup.send("Genius API Key set.", ephemeral=True)

    @playlist_group.command(name="settings")
    @app_commands.checks.has_permissions(administrator=True)
    async def playlist_settings(self, interaction: discord.Interaction):
        """Show the current PlaylistCreator settings."""
        channel_id = await self.config.channel_id()
        user_id = await self.config.user_id()
        spotify_client_id = await self.config.spotify_client_id()
        spotify_playlist_id = await self.config.spotify_playlist_id()
        genius_api_key = await self.config.genius_api_key()

        settings = (
            f"Channel ID: {channel_id}\n"
            f"User ID: {user_id}\n"
            f"Spotify Client ID: {'Set' if spotify_client_id else 'Not set'}\n"
            f"Spotify Client Secret: {'Set' if await self.config.spotify_client_secret() else 'Not set'}\n"
            f"Spotify Playlist ID: {spotify_playlist_id}\n"
            f"Genius API Key: {'Set' if genius_api_key else 'Not set'}\n"
        )
        await interaction.response.send_message(f"Current settings:\n```\n{settings}\n```")

    @playlist_group.command(name="auth")
    @app_commands.checks.has_permissions(administrator=True)
    async def spotify_auth(self, interaction: discord.Interaction):
        """Start the Spotify authentication process."""
        client_id = await self.config.spotify_client_id()
        if not client_id:
            await interaction.response.send_message("Spotify client ID is not set. Please set it first.", ephemeral=True)
            return

        code_verifier = secrets.token_urlsafe(64)
        code_challenge = base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode()).digest()).decode().rstrip('=')

        state = secrets.token_urlsafe(16)
        scope = quote("playlist-modify-public playlist-modify-private")
        redirect_uri = quote("http://localhost:8888/callback")

        auth_url = (
            f"https://accounts.spotify.com/authorize"
            f"?client_id={client_id}"
            f"&response_type=code"
            f"&redirect_uri={redirect_uri}"
            f"&scope={scope}"
            f"&state={state}"
            f"&code_challenge_method=S256"
            f"&code_challenge={code_challenge}"
        )

        view = SpotifyAuthView(self, auth_url)
        await interaction.response.send_message("Click the button below to authenticate with Spotify:", view=view, ephemeral=True)

    @tasks.loop(minutes=5.0)
    async def url_check(self):
        await self.perform_url_check()

    async def perform_url_check(self):
        channel_id = await self.config.channel_id()
        user_id = await self.config.user_id()
        self.logger.info(f"Performing URL check for channel {channel_id} and user {user_id}")
        
        if not channel_id or not user_id:
            self.logger.warning("Channel ID or User ID not set")
            return

        channel = self.bot.get_channel(channel_id)
        user = self.bot.get_user(user_id)

        if not channel or not user:
            self.logger.warning("Could not find channel or user")
            return

        url_dict = defaultdict(list)
        
        last_message_id = await self.config.last_message_id()
        self.logger.info(f"Last processed message ID: {last_message_id}")
        kwargs = {}
        if last_message_id:
            kwargs['after'] = discord.Object(id=int(last_message_id))
        
        message_count = 0
        async for message in channel.history(limit=None, oldest_first=True, **kwargs):
            message_count += 1
            self.logger.info(f"Checking message {message.id} from {message.author.name}")
            urls = re.findall(r'(https://open\.spotify\.com/track/[^\s]+)', message.content)
            if urls:
                self.logger.info(f"Found {len(urls)} Spotify URLs in message {message.id}")
                for url in urls:
                    track_id = self.sanitize_spotify_url(url)
                    if track_id:
                        url_dict[message.author.name].append(track_id)
                        self.logger.info(f"Added track ID {track_id} from {message.author.name}")
            await self.config.last_message_id.set(str(message.id))

        self.logger.info(f"Checked {message_count} messages")
        self.logger.info(f"Found {len(url_dict)} users with Spotify links")
        
        if url_dict:
            track_ids = list(set([track_id for tracks in url_dict.values() for track_id in tracks]))
            self.logger.info(f"Found {len(track_ids)} unique track IDs")
            await self.add_tracks_to_playlist(track_ids)
        else:
            self.logger.info("No new Spotify links found")

    def sanitize_spotify_url(self, url):
        """
        Sanitize and validate a Spotify track URL.
        Returns the track ID if valid, None otherwise.
        """
        match = self.url_pattern.match(url)
        if match:
            return match.group(1)
        return None

    @playlist_group.command(name="clear_added_tracks")
    @app_commands.checks.has_permissions(administrator=True)
    async def clear_added_tracks(self, interaction: discord.Interaction):
        """Clear the list of tracks that have been added to the playlist."""
        await self.config.added_tracks.set([])
        await interaction.response.send_message("The list of added tracks has been cleared.")

    async def get_spotify_token(self, code, code_verifier):
        client_id = await self.config.spotify_client_id()
        client_secret = await self.config.spotify_client_secret()
        redirect_uri = "http://localhost:8888/callback"

        self.logger.info(f"Attempting to exchange code for token. Code: {code[:10]}...")

        async with aiohttp.ClientSession() as session:
            data = {
                "client_id": client_id,
                "client_secret": client_secret,
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": redirect_uri,
                "code_verifier": code_verifier,
            }
            self.logger.info(f"Token exchange data: {data}")

            async with session.post("https://accounts.spotify.com/api/token", data=data) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    self.spotify_token = data["access_token"]
                    self.spotify_token_expiry = datetime.now() + timedelta(seconds=data["expires_in"])
                    await self.config.spotify_refresh_token.set(data["refresh_token"])
                    self.logger.info("Successfully obtained Spotify token")
                    return True
                else:
                    error_text = await resp.text()
                    self.logger.error(f"Failed to get Spotify token. Status: {resp.status}, Response: {error_text}")
                    return False

    async def refresh_spotify_token(self):
        client_id = await self.config.spotify_client_id()
        client_secret = await self.config.spotify_client_secret()
        refresh_token = await self.config.spotify_refresh_token()

        if not refresh_token:
            self.logger.error("No refresh token available. Please re-authenticate.")
            return False

        async with aiohttp.ClientSession() as session:
            async with session.post(
                "https://accounts.spotify.com/api/token",
                data={
                    "grant_type": "refresh_token",
                    "refresh_token": refresh_token,
                    "client_id": client_id,
                    "client_secret": client_secret,
                }
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    self.spotify_token = data["access_token"]
                    self.spotify_token_expiry = datetime.now() + timedelta(seconds=data["expires_in"])
                    if "refresh_token" in data:
                        await self.config.spotify_refresh_token.set(data["refresh_token"])
                    return True
                else:
                    self.logger.error(f"Failed to refresh Spotify token. Status: {resp.status}")
                    return False

    async def get_lyrics(self, track_name, artist_name):
        if not self.genius:
            genius_api_key = await self.config.genius_api_key()
            if not genius_api_key:
                self.logger.error("Genius API key is not set")
                return None
            self.genius = lyricsgenius.Genius(genius_api_key)

        self.logger.info(f"Searching Genius for '{track_name}' by {artist_name}")
        try:
            song = self.genius.search_song(track_name, artist_name)
            if song:
                self.logger.info(f"Found lyrics for '{track_name}' by {artist_name}")
                return song.lyrics
            else:
                self.logger.info(f"No lyrics found for '{track_name}' by {artist_name}")
                return None
        except Exception as e:
            self.logger.error(f"Error fetching lyrics: {str(e)}")
            return None

    def contains_offensive_words(self, lyrics):
        if not lyrics:
            self.logger.info("No lyrics provided to check for offensive words")
            return False
        lowered_lyrics = lyrics.lower()
        for word in OFFENSIVE_WORDS:
            if word in lowered_lyrics:
                self.logger.info(f"Offensive word found: '{word}'")
                return True
        self.logger.info("No offensive words found in lyrics")
        return False

    async def add_tracks_to_playlist(self, track_ids):
        if not await self.ensure_spotify_token():
            return False

        self.logger.info(f"Attempting to add {len(track_ids)} tracks to playlist")
        if not self.spotify_token:
            success = await self.refresh_spotify_token()
            if not success:
                self.logger.error("Failed to refresh Spotify token")
                return False

        playlist_id = await self.config.spotify_playlist_id()
        if not playlist_id:
            self.logger.error("Spotify playlist ID not set")
            return False

        headers = {
            "Authorization": f"Bearer {self.spotify_token}",
            "Content-Type": "application/json"
        }

        self.logger.info("Fetching current tracks in the playlist")
        # Get current tracks in the playlist
        async with aiohttp.ClientSession() as session:
            async with session.get(f"https://api.spotify.com/v1/playlists/{playlist_id}/tracks", headers=headers) as resp:
                if resp.status == 200:
                    playlist_tracks = await resp.json()
                    current_track_ids = [item['track']['id'] for item in playlist_tracks['items']]
                    self.logger.info(f"Playlist currently has {len(current_track_ids)} tracks")
                else:
                    self.logger.error(f"Failed to get current playlist tracks. Status: {resp.status}")
                    return False

        # Get previously added tracks
        added_tracks = await self.config.added_tracks()
        self.logger.info(f"Previously added tracks: {len(added_tracks)}")

        tracks_to_add = []
        for track_id in track_ids:
            self.logger.info(f"Processing track ID: {track_id}")
            if track_id in current_track_ids:
                self.logger.info(f"Track {track_id} already in playlist. Skipping.")
                continue
            if track_id in added_tracks:
                self.logger.info(f"Track {track_id} already added previously. Skipping.")
                continue

            # Get track details
            self.logger.info(f"Fetching details for track {track_id}")
            async with aiohttp.ClientSession() as session:
                async with session.get(f"https://api.spotify.com/v1/tracks/{track_id}", headers=headers) as resp:
                    if resp.status != 200:
                        self.logger.error(f"Failed to get track details for {track_id}. Status: {resp.status}")
                        continue
                    track_data = await resp.json()
            
            track_name = track_data['name']
            artist_name = track_data['artists'][0]['name']
            
            self.logger.info(f"Checking track: '{track_name}' by {artist_name}")
            
            # Get lyrics and check for offensive words
            self.logger.info(f"Fetching lyrics for '{track_name}' by {artist_name}")
            lyrics = await self.get_lyrics(track_name, artist_name)
            if lyrics is None:
                self.logger.info(f"Couldn't find lyrics for '{track_name}' by {artist_name}. Adding to playlist.")
                tracks_to_add.append(track_id)
            elif not self.contains_offensive_words(lyrics):
                self.logger.info(f"No offensive words found in '{track_name}' by {artist_name}. Adding to playlist.")
                tracks_to_add.append(track_id)
            else:
                self.logger.info(f"Skipped track '{track_name}' by {artist_name} due to offensive lyrics")

        self.logger.info(f"Tracks to add after filtering: {len(tracks_to_add)}")

        # Add new tracks in chunks
        chunk_size = 100
        for i in range(0, len(tracks_to_add), chunk_size):
            chunk = tracks_to_add[i:i + chunk_size]
            data = {"uris": [f"spotify:track:{track_id}" for track_id in chunk]}
            
            async with aiohttp.ClientSession() as session:
                async with session.post(f"https://api.spotify.com/v1/playlists/{playlist_id}/tracks", headers=headers, json=data) as resp:
                    if resp.status == 401:
                        self.logger.warning("Spotify token expired, attempting to refresh")
                        success = await self.refresh_spotify_token()
                        if success:
                            headers["Authorization"] = f"Bearer {self.spotify_token}"
                            async with session.post(f"https://api.spotify.com/v1/playlists/{playlist_id}/tracks", headers=headers, json=data) as retry_resp:
                                if retry_resp.status != 201:
                                    error_text = await retry_resp.text()
                                    self.logger.error(f"Failed to add tracks to playlist after token refresh. Status: {retry_resp.status}, Response: {error_text}")
                                    return False
                        else:
                            self.logger.error("Failed to refresh Spotify token")
                            return False
                    elif resp.status != 201:
                        error_text = await resp.text()
                        self.logger.error(f"Failed to add tracks to playlist. Status: {resp.status}, Response: {error_text}")
                        return False
                    else:
                        self.logger.info(f"Successfully added {len(chunk)} tracks to playlist")
                        added_tracks.extend(chunk)

        # Update the list of added tracks in the config
        await self.config.added_tracks.set(added_tracks)
        self.logger.info(f"Updated added_tracks in config. Total: {len(added_tracks)}")
        return True

    @url_check.before_loop
    async def before_url_check(self):
        await self.bot.wait_until_ready()

    @playlist_group.command(name="refresh_spotify_token")
    @app_commands.checks.has_permissions(administrator=True)
    async def refresh_spotify_token(self, interaction: discord.Interaction):
        """Manually refresh the Spotify access token."""
        old_token = self.spotify_token
        new_token = await self.refresh_spotify_token()
        if new_token:
            self.spotify_token = new_token
            await interaction.response.send_message("Spotify token refreshed successfully.")
            self.logger.info("Spotify token refreshed manually")
        else:
            await interaction.response.send_message("Failed to refresh Spotify token. Check your client credentials.")
            self.logger.error("Failed to refresh Spotify token manually")

    @playlist_group.command(name="reset_last_message")
    @app_commands.checks.has_permissions(administrator=True)
    async def reset_last_message(self, interaction: discord.Interaction):
        """Reset the last processed message ID to start checking from the beginning."""
        await self.config.last_message_id.set(None)
        self.logger.info("Last message ID reset to None")
        await interaction.response.send_message("Last processed message ID has been reset. The next URL grab will start from the beginning of the channel history.")

    @playlist_group.command(name="check_spotify_token")
    @app_commands.checks.has_permissions(administrator=True)
    async def check_spotify_token(self, interaction: discord.Interaction):
        """Check the current Spotify token and its scopes."""
        if not self.spotify_token:
            success = await self.refresh_spotify_token()
            if not success:
                await interaction.response.send_message("Failed to refresh Spotify token. Please re-authenticate using [p]spotify_auth")
                return

        headers = {
            "Authorization": f"Bearer {self.spotify_token}",
            "Content-Type": "application/json"
        }

        async with aiohttp.ClientSession() as session:
            async with session.get("https://api.spotify.com/v1/me", headers=headers) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    await interaction.response.send_message(f"Spotify token is valid. User: {data['display_name']}")
                else:
                    error_text = await resp.text()
                    await interaction.response.send_message(f"Failed to check Spotify token. Status: {resp.status}, Response: {error_text}")

    @playlist_group.command(name="check_spotify_config")
    @app_commands.checks.has_permissions(administrator=True)
    async def check_spotify_config(self, interaction: discord.Interaction):
        """Check the current Spotify configuration."""
        client_id = await self.config.spotify_client_id()
        client_secret = await self.config.spotify_client_secret()
        playlist_id = await self.config.spotify_playlist_id()

        await interaction.response.send_message(f"Spotify Client ID: {'Set' if client_id else 'Not set'}\n"
                       f"Spotify Client Secret: {'Set' if client_secret else 'Not set'}\n"
                       f"Spotify Playlist ID: {playlist_id if playlist_id else 'Not set'}")

    async def auto_refresh_token(self):
        while True:
            if self.spotify_token_expiry and self.spotify_token_expiry - datetime.now() < timedelta(minutes=5):
                await self.refresh_spotify_token()
            await asyncio.sleep(60)  # Check every minute

    async def ensure_spotify_token(self):
        if not self.spotify_token or (self.spotify_token_expiry and datetime.now() > self.spotify_token_expiry):
            success = await self.refresh_spotify_token()
            if not success:
                self.logger.error("Failed to refresh Spotify token")
                return False
        return True