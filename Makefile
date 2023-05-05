NAME 		= ft_otp

LIBS		= -L/Users/tomartin/homebrew/Cellar/openssl@3/3.1.0/lib
INCLUDE 	= -I/Users/tomartin/homebrew/Cellar/openssl@3/3.1.0/include/

CXXSTD		= -std=c++17
SANITIZE	= -fsanitize=address	
CXX 		= g++
CXXFLAGS 	= -Wall -Wextra -Werror -g3 $(SANITIZE) $(INCLUDE) $(CXXSTD)
LDFLAGS 	= -lssl -lcrypto $(LIBS) $(SANITIZE)


OBJ_DIR = obj/

SRC = main.cpp otp_generator.cpp AES_g.cpp

OBJ = $(addprefix $(OBJ_DIR), $(SRC:.cpp=.o))

all: $(NAME)

obj:
	@mkdir -p $(OBJ_DIR)

$(OBJ_DIR)%.o: %.cpp | obj
	@$(CXX) $(CXXFLAGS) -c $< -o $@

$(NAME): $(OBJ)
	@$(CXX) $(LDFLAGS) $(OBJ) -o $(NAME)

clean:
	@rm -rf $(OBJ_DIR)

fclean: clean
	@rm -f $(NAME)

re: fclean all
