import re
import aiohttp
from redbot.core import commands, Config
from discord.ext import tasks
from collections import defaultdict
from base64 import b64encode

class URLGrabber(commands.Cog):
    def __init__(self, bot):
        self.bot = bot
        self.config = Config.get_conf(self, identifier=1234567890)
        default_global = {
            "channel_id": None,
            "user_id": None,
            "spotify_client_id": None,
            "spotify_client_secret": None,
            "spotify_playlist_id": None,
            "last_message_id": None,
            "added_tracks": []
        }
        self.config.register_global(**default_global)
        self.url_pattern = re.compile(r'https://open\.spotify\.com/track/([a-zA-Z0-9]+)')
        self.url_check.start()
        self.spotify_token = None

    def cog_unload(self):
        self.url_check.cancel()

    @commands.group()
    async def playlistset(self, ctx):
        """Configure the PlaylistCreator settings."""
        if ctx.invoked_subcommand is None:
            await ctx.send_help(ctx.command)

    @playlistset.command(name="channel")
    async def set_channel(self, ctx, channel_id: int):
        """Set the channel to monitor for Spotify links."""
        await self.config.channel_id.set(channel_id)
        await ctx.send(f"Channel set to {channel_id}")

    @commands.command()
    async def seturldm(self, ctx, user_id: int):
        """Set the user to send grabbed URLs to."""
        await self.config.user_id.set(user_id)
        await ctx.send(f"URL recipient set to user with ID {user_id}")

    @commands.command()
    async def setspotifycredentials(self, ctx, client_id: str, client_secret: str):
        """Set Spotify API credentials."""
        await self.config.spotify_client_id.set(client_id)
        await self.config.spotify_client_secret.set(client_secret)
        await ctx.send("Spotify credentials set.")

    @commands.command()
    async def setspotifyplaylist(self, ctx, playlist_id: str):
        """Set Spotify playlist ID."""
        await self.config.spotify_playlist_id.set(playlist_id)
        await ctx.send(f"Spotify playlist ID set to {playlist_id}")

    @commands.command()
    async def graburl(self, ctx):
        """Manually trigger URL grabbing process."""
        channel_id = await self.config.channel_id()
        user_id = await self.config.user_id()
        if not channel_id or not user_id:
            await ctx.send("Please set both the channel and user ID first.")
            return

        await ctx.send("Manually triggering URL grab...")
        await self.perform_url_check()
        await ctx.send("URL grab complete.")

    @tasks.loop(minutes=5.0)
    async def url_check(self):
        await self.perform_url_check()

    async def perform_url_check(self):
        channel_id = await self.config.channel_id()
        user_id = await self.config.user_id()
        if not channel_id or not user_id:
            return

        channel = self.bot.get_channel(channel_id)
        user = self.bot.get_user(user_id)

        if not channel or not user:
            return

        url_dict = defaultdict(list)
        
        last_message_id = await self.config.last_message_id()
        kwargs = {'after': last_message_id} if last_message_id else {}
        
        async for message in channel.history(limit=None, oldest_first=True, **kwargs):
            urls = self.url_pattern.findall(message.content)
            if urls:
                for url in urls:
                    url_dict[message.author.name].append(url)
            await self.config.last_message_id.set(message.id)

        if url_dict:
            dm_content = "Spotify tracks found in {}:\n\n".format(channel.name)
            for author, track_ids in url_dict.items():
                dm_content += f"**{author}**:\n"
                dm_content += "\n".join(f"https://open.spotify.com/track/{track_id}" for track_id in track_ids)
                dm_content += "\n\n"

            while len(dm_content) > 2000:
                split_index = dm_content.rfind('\n', 0, 2000)
                await user.send(dm_content[:split_index])
                dm_content = dm_content[split_index:].lstrip()

            if dm_content:
                await user.send(dm_content)

            await self.add_tracks_to_playlist(list(set([track_id for tracks in url_dict.values() for track_id in tracks])))

    async def get_spotify_token(self):
        client_id = await self.config.spotify_client_id()
        client_secret = await self.config.spotify_client_secret()
        if not client_id or not client_secret:
            return None

        auth = b64encode(f"{client_id}:{client_secret}".encode()).decode()
        headers = {
            "Authorization": f"Basic {auth}",
            "Content-Type": "application/x-www-form-urlencoded"
        }
        data = {"grant_type": "client_credentials"}

        async with aiohttp.ClientSession() as session:
            async with session.post("https://accounts.spotify.com/api/token", headers=headers, data=data) as resp:
                if resp.status == 200:
                    json_data = await resp.json()
                    return json_data["access_token"]
        return None

    async def add_tracks_to_playlist(self, track_ids):
        if not self.spotify_token:
            self.spotify_token = await self.get_spotify_token()
        if not self.spotify_token:
            return

        playlist_id = await self.config.spotify_playlist_id()
        if not playlist_id:
            return

        headers = {
            "Authorization": f"Bearer {self.spotify_token}",
            "Content-Type": "application/json"
        }

        # Get current tracks in the playlist
        async with aiohttp.ClientSession() as session:
            async with session.get(f"https://api.spotify.com/v1/playlists/{playlist_id}/tracks", headers=headers) as resp:
                if resp.status == 200:
                    playlist_tracks = await resp.json()
                    current_track_ids = [item['track']['id'] for item in playlist_tracks['items']]
                else:
                    return

        # Get previously added tracks
        added_tracks = await self.config.added_tracks()

        # Determine which tracks to add and which to remove
        tracks_to_add = [track_id for track_id in track_ids if track_id not in current_track_ids and track_id not in added_tracks]
        tracks_to_remove = [track_id for track_id in added_tracks if track_id not in current_track_ids]

        # Add new tracks
        if tracks_to_add:
            data = {"uris": [f"spotify:track:{track_id}" for track_id in tracks_to_add]}
            async with aiohttp.ClientSession() as session:
                async with session.post(f"https://api.spotify.com/v1/playlists/{playlist_id}/tracks", headers=headers, json=data) as resp:
                    if resp.status != 201:
                        self.spotify_token = None  # Reset token if request failed
                    else:
                        added_tracks.extend(tracks_to_add)

        # Remove tracks that are no longer in the playlist
        if tracks_to_remove:
            data = {"tracks": [{"uri": f"spotify:track:{track_id}"} for track_id in tracks_to_remove]}
            async with aiohttp.ClientSession() as session:
                async with session.delete(f"https://api.spotify.com/v1/playlists/{playlist_id}/tracks", headers=headers, json=data) as resp:
                    if resp.status == 200:
                        for track_id in tracks_to_remove:
                            added_tracks.remove(track_id)

        # Update the list of added tracks in the config
        await self.config.added_tracks.set(added_tracks)

    @url_check.before_loop
    async def before_url_check(self):
        await self.bot.wait_until_ready()

async def setup(bot):
    await bot.add_cog(URLGrabber(bot))