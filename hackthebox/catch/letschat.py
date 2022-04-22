import requests, sys
from rich.console import Console
from rich.table import Table
from rich.columns import Columns
from rich.panel import Panel
from rich import print

# Welcome to my trash code
class LetsChat:
    def __init__(self, url, token):
        self.api = requests.Session()
        self.token = token
        self.api.headers = {
            'Accept' : 'application/json',
            'Authorization': 'Bearer ' + self.token
        }
        self.url = url
        self.account = ''

    def request(self, **kwargs: dict):
        if 'method' not in kwargs:
            kwargs['method'] = 'GET'
        if 'url' not in kwargs and kwargs['endpoint']:
            kwargs['url'] = '{}/{}'.format(self.url, kwargs['endpoint'])
            del kwargs['endpoint']
        try:    
          return self.api.request(**kwargs)
        except Exception as e:
            print(str(e))
            sys.exit(1)

    def get_account(self):
        self.account = self.request(endpoint='account').json()

    def get_rooms(self):
      return self.request(endpoint='rooms').json()

    def get_room(self, room):
      return self.request(endpoint='rooms/'+room).json()

    def get_room_users(self, room):
      return self.request(endpoint='rooms/'+room+'/users').json()

    def get_room_messages(self, room):
      return self.request(endpoint='rooms/'+room+'/messages').json()

    def get_room_files(self, room):
      return self.request(endpoint='rooms/'+room+'/files').json()

    def get_messages(self):
      return self.request(endpoint='messages').json()

    def get_files(self):
      return self.request(endpoint='files').json()

    def get_users(self):
      return self.request(endpoint='users').json()

    def get_user(self, user):
      return self.request(endpoint='users/'+user).json()
  
    def account_details(self):
        self.get_account()
        open_rooms = [self.get_room(i)['name'] for i in self.account['openRooms']]

        table = Table(title="Account Details")
        table.add_column("Detail", style="cyan", no_wrap=True)
        table.add_column("Info.", style="magenta")

        table.add_row("First Name", self.account['firstName'])
        table.add_row("Last Name", self.account['lastName'])
        table.add_row("Username", self.account['username'])
        table.add_row("Rooms", ', '.join(open_rooms) )
        console = Console()
        console.print(table)
  
    def server_details(self):
        table = Table(title="Server Details")

        table.add_column("Detail", style="cyan", no_wrap=True)
        table.add_column("", style="blue")

        table.add_row("Rooms", ', '.join([str(i['name']) for i in self.get_rooms()]) )
        table.add_row("Users", ', '.join([str(i['username']) for i in self.get_users()]) )
        table.add_row("Files", ', '.join([str(i['name']) for i in self.get_files()]) )

        console = Console()
        console.print(table)

    def server_rooms(self):
        console = Console()
        rooms = self.get_rooms()
        users = self.get_users()

        console.rule("[bold red]Rooms")
        rooms_render = [Panel(user['name'], expand=True) for user in rooms]
        console.print(Columns(rooms_render))

        for i in rooms:
            console.rule(f"[bold red]Room: {i['name']}")
            messages = self.get_room_messages(i['id'])
            for msg in messages:
                print(f"[bold] [red] {[x['username'] for x in users if x['id'] == msg['owner'] ][0] }[/red]: {msg['text']}")
    
if __name__ == '__main__':
    # a = LetsChat('lets.chat', 'token')
    a = LetsChat('', '')
    a.account_details()
    a.server_details()
    a.server_rooms()
