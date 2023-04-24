NAME = ft_otp
CXX = g++
CXXFLAGS = -Wall -Wextra -Werror -g3 -fsanitize=address -lssl -lcrypto

OBJ_DIR = obj/

SRC = main.cpp otp_generator.cpp

OBJ = $(addprefix $(OBJ_DIR), $(SRC:.cpp=.o))

all: $(NAME)

obj:
	@mkdir -p $(OBJ_DIR)

$(OBJ_DIR)%.o: %.cpp | obj
	@$(CXX) $(CXXFLAGS) -c $< -o $@

$(NAME): $(OBJ)
	@$(CXX) $(CXXFLAGS) $(OBJ) -o $(NAME)

clean:
	@rm -rf $(OBJ_DIR)

fclean: clean
	@rm -f $(NAME)

re: fclean all
